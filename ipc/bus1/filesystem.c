/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "domain.h"
#include "filesystem.h"
#include "peer.h"
#include "queue.h"
#include "util.h"

enum { /* static inode numbers */
	BUS1_FS_INO_INVALID,
	BUS1_FS_INO_ROOT,
	BUS1_FS_INO_BUS,
	_BUS1_FS_INO_N,
};

static struct file_system_type bus1_fs_type;
static struct inode *bus1_fs_inode_get(struct super_block *sb,
				       unsigned int ino);

/*
 * Bus-File
 */

static int bus1_fs_bus_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_domain *domain = inode->i_sb->s_fs_info;
	struct bus1_peer *peer;
	int r;

	if (!bus1_domain_acquire(domain))
		return -ESHUTDOWN;

	peer = bus1_peer_new();
	if (IS_ERR(peer)) {
		r = PTR_ERR(peer);
		goto exit;
	}

	file->private_data = peer;
	r = 0;

exit:
	bus1_domain_release(domain);
	return r;
}

static int bus1_fs_bus_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_domain *domain = inode->i_sb->s_fs_info;
	struct bus1_peer *peer = file->private_data;

	bus1_peer_disconnect(peer, domain);
	bus1_peer_free(peer);

	return 0;
}

static long bus1_fs_bus_fop_ioctl(struct file *file,
				  unsigned int cmd,
				  unsigned long arg,
				  bool is_compat)
{
	struct bus1_domain *domain = file_inode(file)->i_sb->s_fs_info;
	struct bus1_peer *peer = file->private_data;
	long r;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
	case BUS1_CMD_RESOLVE:
		/* lock against domain shutdown */
		if (!bus1_domain_acquire(domain))
			return -ESHUTDOWN;

		if (cmd == BUS1_CMD_CONNECT)
			r = bus1_peer_connect(peer, domain, arg);
		else if (cmd == BUS1_CMD_RESOLVE)
			r = bus1_domain_resolve(domain, arg);
		else
			r = -ENOTTY;

		bus1_domain_release(domain);
		break;

	case BUS1_CMD_DISCONNECT:
		/* no arguments allowed, it behaves like the last close() */
		if (arg != 0)
			return -EINVAL;

		return bus1_peer_disconnect(peer, domain);

	case BUS1_CMD_FREE:
	case BUS1_CMD_TRACK:
	case BUS1_CMD_UNTRACK:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		down_read(&peer->rwlock);
		if (!bus1_peer_acquire(peer)) {
			r = -ESHUTDOWN;
		} else {
			r = bus1_peer_info_ioctl(bus1_peer_dereference(peer),
						 peer->id,
						 domain, domain->info,
						 cmd, arg, is_compat);
			bus1_peer_release(peer);
		}
		up_read(&peer->rwlock);
		break;

	default:
		/* handle ENOTTY on the top-level, so user-space can probe */
		return -ENOTTY;
	}

	return r;
}

static unsigned int bus1_fs_bus_fop_poll(struct file *file,
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
	 * whether it was deactivated, yet. In that case, the peer is dead
	 * (either via DISCONNECT or domain teardown). Lastly, we dereference
	 * the peer object (which is rcu-protected). It might be NULL during a
	 * racing DISCONNECT (_very_ unlikely, but lets be safe). If it is not
	 * NULL, the peer is life and active, so it is at least writable. Check
	 * if the queue is non-empty, and then also mark it as readable.
	 */
	rcu_read_lock();
	if (!bus1_active_is_new(&peer->active)) {
		peer_info = rcu_dereference(peer->info);
		if (bus1_active_is_deactivated(&peer->active) ||
		    !peer_info) {
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

static int bus1_fs_bus_fop_mmap(struct file *file, struct vm_area_struct *vma)
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

		r = pool->f->f_op->mmap(pool->f, vma);
	}

	bus1_peer_release(peer);
	return r;
}

static long bus1_fs_bus_fop_ioctl_native(struct file *file,
					 unsigned int cmd,
					 unsigned long arg)
{
	return bus1_fs_bus_fop_ioctl(file, cmd, arg, false);
}

#ifdef CONFIG_COMPAT
static long bus1_fs_bus_fop_ioctl_compat(struct file *file,
					 unsigned int cmd,
					 unsigned long arg)
{
	return bus1_fs_bus_fop_ioctl(file, cmd, arg, true);
}
#endif

const struct file_operations bus1_fs_bus_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fs_bus_fop_open,
	.release =		bus1_fs_bus_fop_release,
	.poll =			bus1_fs_bus_fop_poll,
	.llseek =		noop_llseek,
	.mmap =			bus1_fs_bus_fop_mmap,
	.unlocked_ioctl =	bus1_fs_bus_fop_ioctl_native,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		bus1_fs_bus_fop_ioctl_compat,
#endif
};

static const struct inode_operations bus1_fs_bus_iops = {
	.permission	= generic_permission,
};

/*
 * Directories
 */

static int bus1_fs_dir_fop_iterate(struct file *file, struct dir_context *ctx)
{
	struct bus1_domain *domain = file_inode(file)->i_sb->s_fs_info;

	if (!bus1_domain_acquire(domain))
		return -ESHUTDOWN;

	/*
	 * There is only a single directory per mount, hence, it must be the
	 * root directory. Inside of the root directory, we have 3 entries:
	 * The 2 standard directories (`.', `..') and one fixed entry called
	 * `bus', which is the entry point for new peers.
	 */
	WARN_ON(file->f_path.dentry != file->f_path.dentry->d_sb->s_root);

	if (!dir_emit_dots(file, ctx))
		goto exit;
	if (ctx->pos == 2) {
		if (!dir_emit(ctx, "bus", 3, BUS1_FS_INO_BUS, DT_REG))
			goto exit;
		ctx->pos = 3;
	}

	ctx->pos = INT_MAX;

exit:
	bus1_domain_release(domain);
	return 0;
}

static loff_t bus1_fs_dir_fop_llseek(struct file *file,
				     loff_t offset,
				     int whence)
{
	struct inode *inode = file_inode(file);
	loff_t r;

	/* protect f_off against fop_iterate */
	mutex_lock(&inode->i_mutex);
	r = generic_file_llseek(file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	return r;
}

static const struct file_operations bus1_fs_dir_fops = {
	.read		= generic_read_dir,
	.iterate	= bus1_fs_dir_fop_iterate,
	.llseek		= bus1_fs_dir_fop_llseek,
};

static struct dentry *bus1_fs_dir_iop_lookup(struct inode *dir,
					     struct dentry *dentry,
					     unsigned int flags)
{
	struct bus1_domain *domain = dir->i_sb->s_fs_info;
	struct dentry *old = NULL;
	struct inode *inode;

	if (!bus1_domain_acquire(domain))
		return ERR_PTR(-ESHUTDOWN);

	if (!strcmp(dentry->d_name.name, "bus")) {
		inode = bus1_fs_inode_get(dir->i_sb, BUS1_FS_INO_BUS);
		if (IS_ERR(inode))
			old = ERR_CAST(inode);
		else
			old = d_splice_alias(inode, dentry);
	}

	bus1_domain_release(domain);
	return old;
}

static int bus1_fs_dir_iop_unlink(struct inode *dir, struct dentry *dentry)
{
	struct bus1_domain *domain = dir->i_sb->s_fs_info;

	/*
	 * An unlink() on the `bus' file causes a full, synchronous teardown of
	 * the domain. We only provide this for debug builds, so we can test
	 * the teardown properly. On production builds, it is always rejected
	 * with EPERM (as if .unlink was NULL).
	 */

	if (!strcmp(KBUILD_MODNAME, "bus1"))
		return -EPERM;
	if (strcmp(dentry->d_name.name, "bus"))
		return -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	bus1_domain_teardown(domain);
	clear_nlink(d_inode(dentry));

	return 0;
}

static const struct inode_operations bus1_fs_dir_iops = {
	.permission	= generic_permission,
	.lookup		= bus1_fs_dir_iop_lookup,
	.unlink		= bus1_fs_dir_iop_unlink,
};

/*
 * Inodes
 */

static struct inode *bus1_fs_inode_get(struct super_block *sb,
				       unsigned int ino)
{
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	inode->i_mapping->a_ops = &empty_aops;
	inode->i_atime = inode->i_ctime = inode->i_mtime = CURRENT_TIME;

	switch (ino) {
	case BUS1_FS_INO_ROOT:
		inode->i_mode = 00755;
		inode->i_mode |= S_IFDIR;
		inode->i_op = &bus1_fs_dir_iops;
		inode->i_fop = &bus1_fs_dir_fops;
		set_nlink(inode, 2);
		break;
	case BUS1_FS_INO_BUS:
		inode->i_mode = 00666;
		inode->i_mode |= S_IFREG;
		inode->i_op = &bus1_fs_bus_iops;
		inode->i_fop = &bus1_fs_bus_fops;
		break;
	default:
		WARN(1, "populating invalid inode\n");
		break;
	}

	unlock_new_inode(inode);
	return inode;
}

/*
 * Superblocks
 */

static int bus1_fs_super_dop_revalidate(struct dentry *dentry,
					unsigned int flags)
{
	struct bus1_domain *domain = dentry->d_sb->s_fs_info;

	/*
	 * Revalidation of cached entries is simple. Since all mounts are
	 * static, the only invalidation that can happen is if the whole mount
	 * is deactivated. In that case *anything* is invalid and will never
	 * become valid again.
	 */

	return bus1_active_is_active(&domain->active);
}

static const struct dentry_operations bus1_fs_super_dops = {
	.d_revalidate	= bus1_fs_super_dop_revalidate,
};

static const struct super_operations bus1_fs_super_sops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

static int bus1_fs_super_fill(struct super_block *sb)
{
	struct inode *inode;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = BUS1_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &bus1_fs_super_sops;
	sb->s_d_op = &bus1_fs_super_dops;
	sb->s_time_gran = 1;

	inode = bus1_fs_inode_get(sb, BUS1_FS_INO_ROOT);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		/* d_make_root iput()s the inode on failure */
		return -ENOMEM;
	}

	sb->s_flags |= MS_ACTIVE;
	return 0;
}

static void bus1_fs_super_kill(struct super_block *sb)
{
	struct bus1_domain *domain = sb->s_fs_info;

	if (domain)
		bus1_domain_teardown(domain);
	kill_anon_super(sb);
	bus1_domain_free(domain);
}

static int bus1_fs_super_set(struct super_block *sb, void *data)
{
	int ret;

	ret = set_anon_super(sb, data);
	if (!ret)
		sb->s_fs_info = data;

	return ret;
}

static struct dentry *bus1_fs_super_mount(struct file_system_type *fs_type,
					  int flags,
					  const char *dev_name,
					  void *data)
{
	struct bus1_domain *domain;
	struct super_block *sb;
	int ret;

	domain = bus1_domain_new();
	if (IS_ERR(domain))
		return ERR_CAST(domain);

	sb = sget(&bus1_fs_type, NULL, bus1_fs_super_set, flags, domain);
	if (IS_ERR(sb)) {
		bus1_domain_teardown(domain);
		bus1_domain_free(domain);
		return ERR_CAST(sb);
	}

	WARN_ON(sb->s_fs_info != domain);
	WARN_ON(sb->s_root);

	ret = bus1_fs_super_fill(sb);
	if (ret < 0) {
		/* calls into ->kill_sb() when done */
		deactivate_locked_super(sb);
		return ERR_PTR(ret);
	}

	return dget(sb->s_root);
}

static struct file_system_type bus1_fs_type = {
	.name		= KBUILD_MODNAME "fs",
	.owner		= THIS_MODULE,
	.mount		= bus1_fs_super_mount,
	.kill_sb	= bus1_fs_super_kill,
	.fs_flags	= FS_USERNS_MOUNT,
};

/**
 * bus1_fs_init() - register filesystem
 *
 * This registers a filesystem with the VFS layer. The filesystem is called
 * `KBUILD_MODNAME "fs"', which usually resolves to `bus1fs'. The nameing
 * scheme allows to set KBUILD_MODNAME to `bus2' and you will get an
 * independent filesystem for developers, named `bus2fs'.
 *
 * Each mount of the bus1fs filesystem has an bus1_ns attached. Operations
 * on this mount will only affect the attached namespace. On each mount a new
 * namespace is automatically created and used for this mount exclusively.
 * If you want to share a namespace across multiple mounts, you need to
 * bind-mount it.
 *
 * Mounts of bus1fs (with a different namespace each) are unrelated to each
 * other and will never have any effect on any namespace but their own.
 *
 * Return: 0 on success, negative error otherwise.
 */
int __init bus1_fs_init(void)
{
	return register_filesystem(&bus1_fs_type);
}

/**
 * bus1_fs_exit() - unregister filesystem
 *
 * This does the reverse to bus1_fs_init(). It unregisters the bus1
 * filesystem from VFS and cleans up any allocated resources.
 */
void __exit bus1_fs_exit(void)
{
	unregister_filesystem(&bus1_fs_type);
}
