/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include "main.h"
#include "util.h"

/**
 * bus1_import_vecs() - import vectors from user
 * @out_vecs:		kernel memory to store vecs, preallocated
 * @out_length:		output storage for sum of all vectors lengths
 * @vecs:		user pointer for vectors
 * @n_vecs:		number of vectors to import
 *
 * This copies the given vectors from user memory into the preallocated kernel
 * buffer. Sanity checks are performed on the memory of the vector-array, the
 * memory pointed to by the vectors and on the overall size calculation.
 *
 * If the vectors were copied successfully, @out_length will contain the sum of
 * all vector-lengths.
 *
 * Unlike most other functions, this function might modify its output buffer
 * even if it fails. That is, @out_vecs might contain garbage if this function
 * fails. This is done for performance reasons.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs)
{
	size_t i, length = 0;

	if (n_vecs > UIO_MAXIOV)
		return -EMSGSIZE;
	if (n_vecs == 0) {
		*out_length = 0;
		return 0;
	}

	if (IS_ENABLED(CONFIG_COMPAT) && in_compat_syscall()) {
		/*
		 * Compat types and macros are protected by CONFIG_COMPAT,
		 * rather than providing a fallback. We want compile-time
		 * coverage, so provide fallback types. The IS_ENABLED(COMPAT)
		 * condition guarantees this is collected by the dead-code
		 * elimination, anyway.
		 */
#if IS_ENABLED(CONFIG_COMPAT)
		const struct compat_iovec __user *uvecs = vecs;
		compat_uptr_t v_base;
		compat_size_t v_len;
		compat_ssize_t v_slen;
#else
		const struct iovec __user *uvecs = vecs;
		void __user *v_base;
		size_t v_len;
		ssize_t v_slen;
#endif
		void __user *v_ptr;

		if (unlikely(!access_ok(VERIFY_READ, vecs,
					sizeof(*uvecs) * n_vecs)))
			return -EFAULT;

		for (i = 0; i < n_vecs; ++i) {
			if (unlikely(__get_user(v_base, &uvecs[i].iov_base) ||
				     __get_user(v_len, &uvecs[i].iov_len)))
				return -EFAULT;

#if IS_ENABLED(CONFIG_COMPAT)
			v_ptr = compat_ptr(v_base);
#else
			v_ptr = v_base;
#endif
			v_slen = v_len;

			if (unlikely(v_slen < 0 ||
				     (typeof(v_len))v_slen != v_len))
				return -EMSGSIZE;
			if (unlikely(!access_ok(VERIFY_READ, v_ptr, v_len)))
				return -EFAULT;
			if (unlikely((size_t)v_len > MAX_RW_COUNT - length))
				return -EMSGSIZE;

			out_vecs[i].iov_base = v_ptr;
			out_vecs[i].iov_len = v_len;
			length += v_len;
		}
	} else {
		void __user *v_base;
		size_t v_len;

		if (copy_from_user(out_vecs, vecs, sizeof(*out_vecs) * n_vecs))
			return -EFAULT;

		for (i = 0; i < n_vecs; ++i) {
			v_base = out_vecs[i].iov_base;
			v_len = out_vecs[i].iov_len;

			if (unlikely((ssize_t)v_len < 0))
				return -EMSGSIZE;
			if (unlikely(!access_ok(VERIFY_READ, v_base, v_len)))
				return -EFAULT;
			if (unlikely(v_len > MAX_RW_COUNT - length))
				return -EMSGSIZE;

			length += v_len;
		}
	}

	*out_length = length;
	return 0;
}

/**
 * bus1_import_fd() - import file descriptor from user
 * @user_fd:	pointer to user-supplied file descriptor
 *
 * This imports a file-descriptor from the current user-context. The FD number
 * is copied into kernel-space, then resolved to a file and returned to the
 * caller. If something goes wrong, an error is returned.
 *
 * Neither bus1, nor UDS files are allowed. If those are supplied, EOPNOTSUPP
 * is returned. Those would require expensive garbage-collection if they're
 * sent recursively by user-space.
 *
 * Return: Pointer to pinned file, ERR_PTR on failure.
 */
struct file *bus1_import_fd(const u32 __user *user_fd)
{
	struct file *f, *ret;
	struct socket *sock;
	struct inode *inode;
	int fd;

	if (unlikely(get_user(fd, user_fd)))
		return ERR_PTR(-EFAULT);
	if (unlikely(fd < 0))
		return ERR_PTR(-EBADF);

	f = fget_raw(fd);
	if (unlikely(!f))
		return ERR_PTR(-EBADF);

	inode = file_inode(f);
	sock = S_ISSOCK(inode->i_mode) ? SOCKET_I(inode) : NULL;

	if (f->f_mode & FMODE_PATH)
		ret = f; /* O_PATH is always allowed */
	else if (f->f_op == &bus1_fops)
		ret = ERR_PTR(-EOPNOTSUPP); /* disallow bus1 recursion */
	else if (sock && sock->sk && sock->ops && sock->ops->family == PF_UNIX)
		ret = ERR_PTR(-EOPNOTSUPP); /* disallow UDS recursion */
	else
		ret = f; /* all others are allowed */

	if (f != ret)
		fput(f);

	return ret;
}

/*
 * bus1_clone_file() - clone an existing file
 * @file:		file to clone
 *
 * Allocate a new file given an existing file template. The file will have the
 * same properties as the existing file, but is not linked to any context. The
 * caller will get an exclusive reference to the file.
 *
 * Note that this does *not* call open() on the file. The caller has to do that
 * themself. Furthermore, so far we only allow to call this on bus1_fops
 * character devices. Other file types might have external dependencies which
 * we cannot predict.
 *
 * Return: Pointer to new file, ERR_PTR on failure.
 */
struct file *bus1_clone_file(struct file *file)
{
	struct inode *inode = file->f_inode;
	const struct file_operations *fops = NULL;
	struct file *clone = NULL;
	struct cdev *cdev = NULL;
	int r;

	/*
	 * Make sure this is not called on random files. Some files might
	 * request random references (like block-devices or pipes), which we
	 * cannot serve.
	 */
	if (WARN_ON(file->f_op != &bus1_fops))
		return ERR_PTR(-ENOTRECOVERABLE);

	fops = fops_get(file->f_op);
	if (!fops)
		return ERR_PTR(-ENODEV);

	/*
	 * Unfortunately, alloc_file() does not take the cdev-reference, but
	 * fput() drops it. As cdev_get() is non-public, we just copy the logic
	 * here.
	 */
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev &&
		     !(file->f_mode & FMODE_PATH))) {
		if (!try_module_get(inode->i_cdev->owner)) {
			r = -ENODEV;
			goto error;
		}
		cdev = inode->i_cdev;
		kobject_get(&cdev->kobj);
	}

	clone = alloc_file(&file->f_path,
			   file->f_mode & (FMODE_READ | FMODE_WRITE), fops);
	if (IS_ERR(clone)) {
		r = PTR_ERR(clone);
		clone = NULL;
		goto error;
	}

	/* alloc_file() consumes references of its arguments */
	path_get(&file->f_path);
	clone->f_flags |= file->f_flags & (O_RDWR | O_LARGEFILE);

	return clone;

error:
	if (cdev) {
		kobject_put(&cdev->kobj);
		module_put(cdev->owner);
	}
	fops_put(fops);
	return ERR_PTR(r);
}

#if defined(CONFIG_DEBUG_FS)

static int bus1_debugfs_atomic_t_get(void *data, u64 *val)
{
	*val = atomic_read((atomic_t *)data);
	return 0;
}

#if defined(DEFINE_DEBUGFS_ATTRIBUTE)
DEFINE_DEBUGFS_ATTRIBUTE(bus1_debugfs_atomic_x_ro,
			 bus1_debugfs_atomic_t_get,
			 NULL,
			 "%llx\n");
#else
DEFINE_SIMPLE_ATTRIBUTE(bus1_debugfs_atomic_x_ro,
			bus1_debugfs_atomic_t_get,
			NULL,
			"%llx\n");
#endif

/**
 * bus1_debugfs_create_atomic_x() - create debugfs file for hex atomic_t
 * @name:	file name to use
 * @mode:	permissions for the file
 * @parent:	parent directory
 * @value:	variable to read from, or write to
 *
 * This is almost equivalent to debugfs_create_atomic_t() but prints/reads the
 * data as hexadecimal value. So far, only read-only attributes are supported.
 *
 * XXX: With linux-4.7 srcu-protected debugfs files are introduced. Switch over
 *      once released and drop the #ifdef guards we have in place right now.
 *
 * Return: Pointer to new dentry, NULL/ERR_PTR if disabled or on failure.
 */
struct dentry *bus1_debugfs_create_atomic_x(const char *name,
					    umode_t mode,
					    struct dentry *parent,
					    atomic_t *value)
{
#if defined(DEFINE_DEBUGFS_ATTRIBUTE)
	return debugfs_create_file_unsafe(name, mode, parent, value,
					  &bus1_debugfs_atomic_x_ro);
#else
	return debugfs_create_file(name, mode, parent, value,
				   &bus1_debugfs_atomic_x_ro);
#endif
}

#endif /* defined(CONFIG_DEBUG_FS) */
