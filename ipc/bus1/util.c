/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
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
struct file *bus1_import_fd(int fd)
{
	struct file *f, *ret;
	struct socket *sock;
	struct inode *inode;

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

#if defined(CONFIG_DEBUG_FS)

static int bus1_debugfs_atomic_t_get(void *data, u64 *val)
{
	*val = atomic_read((atomic_t *)data);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(bus1_debugfs_atomic_x_ro,
			 bus1_debugfs_atomic_t_get,
			 NULL,
			 "%llx\n");

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
 * Return: Pointer to new dentry, NULL/ERR_PTR if disabled or on failure.
 */
struct dentry *bus1_debugfs_create_atomic_x(const char *name,
					    umode_t mode,
					    struct dentry *parent,
					    atomic_t *value)
{
	return debugfs_create_file_unsafe(name, mode, parent, value,
					  &bus1_debugfs_atomic_x_ro);
}

#endif /* defined(CONFIG_DEBUG_FS) */
