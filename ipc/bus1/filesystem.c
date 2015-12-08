/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/dcache.h>
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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "filesystem.h"
#include "peer.h"

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
 * Mounts
 */

struct bus1_fs_mount {
	wait_queue_head_t waitq;
	struct bus1_active active;
};

static struct bus1_fs_mount *bus1_fs_mount_new(void)
{
	struct bus1_fs_mount *mount;

	mount = kmalloc(sizeof(*mount), GFP_KERNEL);
	if (!mount)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&mount->waitq);
	bus1_active_init(&mount->active);

	return mount;
}

static struct bus1_fs_mount *
bus1_fs_mount_free(struct bus1_fs_mount *mount)
{
	if (!mount)
		return NULL;

	kfree(mount);

	return NULL;
}

static void bus1_fs_mount_shutdown(struct bus1_fs_mount *mount)
{
}

/*
 * Handles
 */

struct bus1_fs_handle {
	struct mutex lock;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer *peer;
};

static struct bus1_fs_handle *bus1_fs_handle_new(void)
{
	struct bus1_fs_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	mutex_init(&handle->lock);
	init_waitqueue_head(&handle->waitq);
	bus1_active_init(&handle->active);
	handle->peer = NULL;

	return handle;
}

static void bus1_fs_handle_release(struct bus1_active *active)
{
	struct bus1_fs_handle *handle = container_of(active,
						     struct bus1_fs_handle,
						     active);

	/*
	 * This function is called by bus1_active_drain(), once all active
	 * references to the handle are drained. In that case, we know that
	 * no-one can hold a pointer to the peer, anymore. Hence, we simply
	 * destroy the peer and reset it to NULL.
	 */

	handle->peer = bus1_peer_free(handle->peer);
}

static struct bus1_fs_handle *
bus1_fs_handle_free(struct bus1_fs_handle *handle)
{
	if (!handle)
		return NULL;

	/* in case it wasn't deactivated, yet, do that now */
	bus1_active_deactivate(&handle->active);
	bus1_active_drain(&handle->active, &handle->waitq,
			  bus1_fs_handle_release);

	WARN_ON(handle->peer);
	mutex_destroy(&handle->lock);
	kfree(handle);

	return NULL;
}

static int bus1_fs_handle_connect(struct bus1_fs_handle *handle,
				  struct bus1_fs_mount *mount,
				  unsigned long arg)
{
	int r = 0;

	mutex_lock(&handle->lock); /* lock against parallel CONNECT */

	if (bus1_active_is_new(&handle->active)) {
		/* connect new peer */
		handle->peer = bus1_peer_new();
		if (IS_ERR(handle->peer)) {
			r = PTR_ERR(handle->peer);
			handle->peer = NULL;
			goto exit;
		}

		bus1_active_activate(&handle->active);
	} else if (bus1_active_is_active(&handle->active)) {
		/* XXX: reset existing peer */
	} else {
		/* peer was already shut down */
		r = -ESHUTDOWN;
	}

exit:
	mutex_unlock(&handle->lock);
	return r;
}

static int bus1_fs_handle_disconnect(struct bus1_fs_handle *handle,
				     unsigned long arg)
{
	int r;

	mutex_lock(&handle->lock); /* lock against parallel CONNECT */
	bus1_active_deactivate(&handle->active);
	/* only the first to drain will yield success */
	if (bus1_active_drain(&handle->active, &handle->waitq,
			      bus1_fs_handle_release))
		r = 0;
	else
		r = -ESHUTDOWN;
	mutex_unlock(&handle->lock);

	return r;
}

/*
 * Bus-File
 */

static int bus1_fs_bus_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_fs_mount *mount = inode->i_sb->s_fs_info;
	struct bus1_fs_handle *handle;
	int r;

	/*
	 * As long as you can call open(), the mount is active and as such the
	 * superblock is as well. Hence, @mount is valid and fully accessible.
	 * However, we still acquire an active-reference of the mount for the
	 * time being. This allows us to easily shutdown a whole mount by
	 * simply disabling the active-counter.
	 */
	if (!bus1_active_acquire(&mount->active))
		return -ESHUTDOWN;

	handle = bus1_fs_handle_new();
	if (IS_ERR(handle)) {
		r = PTR_ERR(handle);
		goto exit;
	}

	file->private_data = handle;
	r = 0;

exit:
	bus1_active_release(&mount->active, &mount->waitq);
	return r;
}

static int bus1_fs_bus_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_fs_handle *handle = file->private_data;

	bus1_fs_handle_free(handle);
	return 0;
}

static long bus1_fs_bus_fop_ioctl(struct file *file,
				  unsigned int cmd,
				  unsigned long arg)
{
	struct bus1_fs_mount *mount = file_inode(file)->i_sb->s_fs_info;
	struct bus1_fs_handle *handle = file->private_data;
	long r;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
		return bus1_fs_handle_connect(handle, mount, arg);

	case BUS1_CMD_DISCONNECT:
		return bus1_fs_handle_disconnect(handle, arg);

	case BUS1_CMD_FREE:
	case BUS1_CMD_RESOLVE:
	case BUS1_CMD_TRACK:
	case BUS1_CMD_UNTRACK:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		if (!bus1_active_acquire(&handle->active))
			return -ESHUTDOWN;

		/* XXX: forward to peer */
		r = 0;
		bus1_active_release(&handle->active, &handle->waitq);
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
	struct bus1_fs_handle *handle = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	if (bus1_active_is_active(&handle->active)) {
		poll_wait(file, &handle->waitq, wait);
		if (0) /* XXX: is-readable */
			mask |= POLLIN | POLLRDNORM;
	} else {
		mask = POLLERR | POLLHUP;
	}

	return mask;
}

static int bus1_fs_bus_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* XXX: forward to peer */
	return -EINVAL;
}

static const struct file_operations bus1_fs_bus_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fs_bus_fop_open,
	.release =		bus1_fs_bus_fop_release,
	.poll =			bus1_fs_bus_fop_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	bus1_fs_bus_fop_ioctl,
	.mmap =			bus1_fs_bus_fop_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		bus1_fs_bus_fop_ioctl,
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
	struct bus1_fs_mount *mount = file_inode(file)->i_sb->s_fs_info;

	if (bus1_active_acquire(&mount->active))
		return -ESHUTDOWN;

	/*
	 * There is only a single directory per mount, hence, it must be the
	 * root directory. Inside of the root directory, we have 3 entires:
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
	bus1_active_release(&mount->active, &mount->waitq);
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
	struct bus1_fs_mount *mount = dir->i_sb->s_fs_info;
	struct dentry *old = NULL;
	struct inode *inode;

	if (bus1_active_acquire(&mount->active))
		return ERR_PTR(-ESHUTDOWN);

	if (!strcmp(dentry->d_name.name, "bus")) {
		inode = bus1_fs_inode_get(dir->i_sb, BUS1_FS_INO_BUS);
		if (IS_ERR(inode))
			old = ERR_CAST(inode);
		else
			old = d_splice_alias(inode, dentry);
	}

	bus1_active_release(&mount->active, &mount->waitq);
	return old;
}

static const struct inode_operations bus1_fs_dir_iops = {
	.permission	= generic_permission,
	.lookup		= bus1_fs_dir_iop_lookup,
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

	/* XXX: default permissions? (uid/gid is root) */
	inode->i_mode = S_IALLUGO;

	switch (ino) {
	case BUS1_FS_INO_ROOT:
		inode->i_mode |= S_IFDIR;
		inode->i_op = &bus1_fs_dir_iops;
		inode->i_fop = &bus1_fs_dir_fops;
		set_nlink(inode, 2);
		break;
	case BUS1_FS_INO_BUS:
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
	struct bus1_fs_mount *mount = dentry->d_sb->s_fs_info;

	/*
	 * Revalidation of cached entries is simple. Since all mounts are
	 * static, the only invalidation that can happen is if the whole mount
	 * is deactivated. In that case *anything* is invalid and will never
	 * become valid again.
	 */

	return bus1_active_is_active(&mount->active);
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
	struct bus1_fs_mount *mount = sb->s_fs_info;
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

	bus1_active_activate(&mount->active);
	sb->s_flags |= MS_ACTIVE;
	return 0;
}

static void bus1_fs_super_kill(struct super_block *sb)
{
	struct bus1_fs_mount *mount = sb->s_fs_info;

	if (mount)
		bus1_fs_mount_shutdown(mount);
	kill_anon_super(sb);
	bus1_fs_mount_free(mount);
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
	struct super_block *sb;
	struct bus1_fs_mount *mount;
	int ret;

	mount = bus1_fs_mount_new();
	if (IS_ERR(mount))
		return ERR_CAST(mount);

	sb = sget(&bus1_fs_type, NULL, bus1_fs_super_set, flags, mount);
	if (IS_ERR(sb)) {
		bus1_fs_mount_shutdown(mount);
		bus1_fs_mount_free(mount);
		return ERR_CAST(sb);
	}

	WARN_ON(sb->s_fs_info != mount);
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
