/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "main.h"
#include "peer.h"
#include "queue.h"
#include "tests.h"
#include "user.h"
#include "util.h"

static int bus1_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_peer *peer;
	int r;

	peer = bus1_peer_new();
	if (IS_ERR(peer))
		return PTR_ERR(peer);

	r = bus1_peer_connect(peer);
	if (r < 0) {
		bus1_peer_free(peer);
		return r;
	}

	file->private_data = peer;
	return 0;
}

static int bus1_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_peer *peer = file->private_data;

	bus1_peer_disconnect(peer);
	bus1_peer_free(peer);

	return 0;
}

static unsigned int bus1_fop_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	struct bus1_peer *peer = file->private_data;
	struct bus1_peer_info *peer_info;
	unsigned int mask;

	poll_wait(file, &peer->waitq, wait);

	/*
	 * We now dereference the peer object (which is rcu-protected). It
	 * might be NULL during a racing DISCONNECT. If it is non-NULL *and*
	 * the peer has not been deactivated, then the peer is live and thus
	 * writable. If data is queued, it is readable as well.
	 */
	rcu_read_lock();
	peer_info = rcu_dereference(peer->info);
	if (!peer_info || bus1_active_is_deactivated(&peer->active)) {
		mask = POLLERR | POLLHUP;
	} else {
		mask = POLLOUT | POLLWRNORM;
		if (bus1_queue_is_readable(&peer_info->queue))
			mask |= POLLIN | POLLRDNORM;
	}
	rcu_read_unlock();

	return mask;
}

static int bus1_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct bus1_peer *peer = file->private_data;
	struct bus1_pool *pool;
	int r;

	if (!bus1_peer_acquire(peer))
		return -ESHUTDOWN;

	pool = &bus1_peer_dereference(peer)->pool;

	if (vma->vm_flags & VM_WRITE) {
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
	struct bus1_peer *peer = file->private_data;
	int r;

	switch (cmd) {
	case BUS1_CMD_PEER_INIT:
	case BUS1_CMD_PEER_QUERY:
	case BUS1_CMD_PEER_RESET:
	case BUS1_CMD_PEER_CLONE:
	case BUS1_CMD_NODE_DESTROY:
	case BUS1_CMD_HANDLE_RELEASE:
	case BUS1_CMD_SLICE_RELEASE:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		if (!bus1_peer_acquire(peer))
			return -ESHUTDOWN;
		r = bus1_peer_ioctl(peer, file, cmd, arg);
		bus1_peer_release(peer);
		return r;
	}

	return -ENOTTY;
}

static void bus1_fop_show_fdinfo(struct seq_file *m, struct file *file)
{
	struct bus1_peer *peer = file->private_data;

	seq_printf(m, KBUILD_MODNAME "-peer:\t%16llx\n", peer->id);
}

const struct file_operations bus1_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fop_open,
	.release =		bus1_fop_release,
	.poll =			bus1_fop_poll,
	.llseek =		noop_llseek,
	.mmap =			bus1_fop_mmap,
	.unlocked_ioctl =	bus1_fop_ioctl,
	.compat_ioctl =		bus1_fop_ioctl,
	.show_fdinfo =		bus1_fop_show_fdinfo,
};

static struct miscdevice bus1_misc = {
	.fops		= &bus1_fops,
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= KBUILD_MODNAME,
	.mode		= S_IRUGO | S_IWUGO,
};

struct dentry *bus1_debugdir;

static int __init bus1_init(void)
{
	int r;

	bus1_tests_run();

	bus1_debugdir = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!bus1_debugdir)
		pr_err("cannot create debugfs root\n");

	r = misc_register(&bus1_misc);
	if (r < 0)
		goto error;

	pr_info("initialized\n");
	return 0;

error:
	debugfs_remove(bus1_debugdir);
	return r;
}

static void __exit bus1_exit(void)
{
	WARN_ON(!idr_is_empty(&bus1_user_ida.idr));
	WARN_ON(!idr_is_empty(&bus1_user_idr));

	misc_deregister(&bus1_misc);
	debugfs_remove(bus1_debugdir);
	ida_destroy(&bus1_user_ida);
	idr_destroy(&bus1_user_idr);
}

module_init(bus1_init);
module_exit(bus1_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bus based interprocess communication");
