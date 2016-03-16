#ifndef __BUS1_UTIL_H
#define __BUS1_UTIL_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Utilities
 *
 * Random untility functions that don't belong to a specific object. Some of
 * them are copies from internal kernel functions (which lack an export
 * annotation), some of them are variants of internal kernel functions, and
 * some of them are our own.
 */

#include <linux/kernel.h>
#include <linux/uio.h>

int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs,
		     bool is_compat);
struct file *bus1_import_fd(const u32 __user *user_fd);
struct file *bus1_clone_file(struct file *file);
bool bus1_in_compat_syscall(void);

/**
 * bus1_import_fixed_ioctl() - copy fixed-size ioctl payload from user
 * @dst:	destination to copy data to
 * @src:	user address to copy from
 * @size:	exact size of the ioctl payload
 *
 * Copy ioctl payload from user-space into kernel-space. Backing memory must be
 * pre-allocated by the caller, alignment restrictions are checked.
 *
 * Return: 0 on success, negative error code on failure.
 */
static inline int bus1_import_fixed_ioctl(void *dst, unsigned long src,
					  size_t size)
{
	if (src & 0x7)
		return -EFAULT;
	if (copy_from_user(dst, (void __user *)src, size))
		return -EFAULT;
	return 0;
}

#endif /* __BUS1_UTIL_H */
