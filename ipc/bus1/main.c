/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "main.h"
#include "peer.h"
#include "tests.h"
#include "user.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

static int bus1_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_peer *peer;

	peer = bus1_peer_new(current_cred());
	if (IS_ERR(peer))
		return PTR_ERR(peer);

	file->private_data = peer;
	return 0;
}

static int bus1_fop_release(struct inode *inode, struct file *file)
{
	bus1_peer_free(file->private_data);
	return 0;
}

static unsigned int bus1_fop_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	struct bus1_peer *peer = file->private_data;
	unsigned int mask;

	poll_wait(file, &peer->waitq, wait);

	/* access queue->front unlocked */
	rcu_read_lock();
	if (bus1_active_is_deactivated(&peer->active)) {
		mask = POLLHUP;
	} else {
		mask = POLLOUT | POLLWRNORM;
		if (bus1_queue_is_readable_rcu(&peer->data.queue))
			mask |= POLLIN | POLLRDNORM;
	}
	rcu_read_unlock();

	return mask;
}

static int bus1_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct bus1_peer *peer = file->private_data;
	int r;

	if (!bus1_peer_acquire(peer))
		return -ESHUTDOWN;

	r = bus1_pool_mmap(&peer->data.pool, vma);
	bus1_peer_release(peer);
	return r;
}

static void bus1_fop_show_fdinfo(struct seq_file *m, struct file *file)
{
	struct bus1_peer *peer = file->private_data;

	seq_printf(m, KBUILD_MODNAME "-peer:\t%16llx\n", peer->id);
}

const struct file_operations bus1_fops = {
	.owner			= THIS_MODULE,
	.open			= bus1_fop_open,
	.release		= bus1_fop_release,
	.poll			= bus1_fop_poll,
	.llseek			= noop_llseek,
	.mmap			= bus1_fop_mmap,
	.unlocked_ioctl		= bus1_peer_ioctl,
	.compat_ioctl		= bus1_peer_ioctl,
	.show_fdinfo		= bus1_fop_show_fdinfo,
};

static struct miscdevice bus1_misc = {
	.fops			= &bus1_fops,
	.minor			= MISC_DYNAMIC_MINOR,
	.name			= KBUILD_MODNAME,
	.mode			= S_IRUGO | S_IWUGO,
};

struct dentry *bus1_debugdir;

static int __init bus1_modinit(void)
{
	int r;

	r = bus1_tests_run();
	if (r < 0)
		return r;

	bus1_debugdir = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!bus1_debugdir)
		pr_err("cannot create debugfs root\n");

	r = misc_register(&bus1_misc);
	if (r < 0)
		goto error;

	pr_info("loaded\n");
	return 0;

error:
	debugfs_remove(bus1_debugdir);
	bus1_user_modexit();
	return r;
}

static void __exit bus1_modexit(void)
{
	misc_deregister(&bus1_misc);
	debugfs_remove(bus1_debugdir);
	bus1_user_modexit();
	pr_info("unloaded\n");
}

module_init(bus1_modinit);
module_exit(bus1_modexit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bus based interprocess communication");
