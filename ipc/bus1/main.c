/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "active.h"
#include "main.h"
#include "peer.h"
#include "queue.h"

static int bus1_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_peer *peer;

	peer = bus1_peer_new();
	if (IS_ERR(peer))
		return PTR_ERR(peer);

	file->private_data = peer;
	return 0;
}

static int bus1_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_peer *peer = file->private_data;

	bus1_peer_teardown(peer);
	bus1_peer_free(peer);

	return 0;
}

static unsigned int bus1_fop_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	struct bus1_peer *peer = file->private_data;
	struct bus1_peer_info *peer_info;
	unsigned int mask = 0;

	poll_wait(file, &peer->waitq, wait);

	/*
	 * If the peer is still in state NEW, then CONNECT hasn't been called
	 * and the peer is unused. Return no event at all.
	 * If the peer is not NEW, then CONNECT *was* called. We then check
	 * whether it was deactivated, yet. In that case, the peer is dead.
	 * Lastly, we dereference the peer object (which is rcu-protected). It
	 * might be NULL during a racing DISCONNECT (_very_ unlikely, but lets
	 * be safe). If it is not NULL, the peer is live and active, so it is
	 * at least writable. Check if the queue is non-empty, and then also
	 * mark it as readable.
	 */
	rcu_read_lock();
	if (!bus1_active_is_new(&peer->active)) {
		peer_info = rcu_dereference(peer->info);
		if (bus1_active_is_deactivated(&peer->active) || !peer_info) {
			mask = POLLERR | POLLHUP;
		} else {
			mask = POLLOUT | POLLWRNORM;
			if (bus1_queue_peek_rcu(&peer_info->queue))
				mask |= POLLIN | POLLRDNORM;
		}
	}
	rcu_read_unlock();

	return mask;
}

static int bus1_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct bus1_peer *peer = file->private_data;
	struct bus1_pool *pool;
	int r;

	/*
	 * We don't lock peer->rwlock, as it is not needed, and we really
	 * don't want to order it below mmap_sem. Pinning the peer is
	 * sufficient to guarantee the pool is accessible and will not go away.
	 */

	if (!bus1_peer_acquire(peer))
		return -ESHUTDOWN;

	pool = &bus1_peer_dereference(peer)->pool;

	if ((vma->vm_end - vma->vm_start) > pool->size) {
		/* do not allow to map more than the size of the file */
		r = -EFAULT;
	} else if (vma->vm_flags & VM_WRITE) {
		/* deny write access to the pool */
		r = -EPERM;
	} else {
		/* replace the connection file with our shmem file */
		if (vma->vm_file)
			fput(vma->vm_file);

		vma->vm_file = get_file(pool->f);
		vma->vm_flags &= ~VM_MAYWRITE;

		/* calls into shmem_mmap(), which simply sets vm_ops */
		r = pool->f->f_op->mmap(pool->f, vma);
	}

	bus1_peer_release(peer);
	return r;
}

static long bus1_fop_ioctl(struct file *file,
			   unsigned int cmd,
			   unsigned long arg)
{
	return bus1_peer_ioctl(file->private_data, file, cmd, arg);
}

const struct file_operations bus1_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fop_open,
	.release =		bus1_fop_release,
	.poll =			bus1_fop_poll,
	.llseek =		noop_llseek,
	.mmap =			bus1_fop_mmap,
	.unlocked_ioctl =	bus1_fop_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		bus1_fop_ioctl,
#endif
};

static struct miscdevice bus1_misc = {
	.fops		= &bus1_fops,
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= KBUILD_MODNAME,
};

static int __init bus1_init(void)
{
	int r;

	r = misc_register(&bus1_misc);
	if (r < 0)
		return r;

	pr_info("initialized\n");
	return 0;
}

static void __exit bus1_exit(void)
{
	misc_deregister(&bus1_misc);
}

module_init(bus1_init);
module_exit(bus1_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bus based interprocess communication");
MODULE_ALIAS("devname:" KBUILD_MODNAME);
