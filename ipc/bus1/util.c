/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "main.h"
#include "util.h"

/**
 * bus1_import_fixed_ioctl() - copy fixed-size ioctl payload from user
 * @arg:	user-provided ioctl argument
 * @size:	exact size of the ioctl payload
 *
 * Copy ioctl payload from user-space into kernel-space. Backing memory is
 * dynamically allocated, alignment restrictions are checked.
 *
 * Return: Pointer to dynamically allocated payload, ERR_PTR on failure.
 */
void *bus1_import_fixed_ioctl(unsigned long arg, size_t size)
{
	if (arg & 0x7)
		return ERR_PTR(-EFAULT);

	return memdup_user((void __user *)arg, size);
}

/**
 * bus1_import_dynamic_ioctl() - copy dynamic-size ioctl payload from user
 * @arg:	user-provided ioctl argument
 * @min_size:	minimum size of the ioctl payload
 *
 * Copy ioctl payload from user-space into kernel-space. The first 8 bytes of
 * the ioctl payload must contain the actual size of the payload. Data is thus
 * copied in two steps: First the size is copied into kernel-space, then the
 * whole payload is copied into an allocated buffer.
 *
 * Alignment restrictions are checked.
 *
 * Return: Pointer to dynamically allocated payload, ERR_PTR on failure.
 */
void *bus1_import_dynamic_ioctl(unsigned long arg, size_t min_size)
{
	void *param;
	u64 size;

	if (WARN_ON(min_size < sizeof(u64)))
		return ERR_PTR(-EFAULT);
	if ((arg & 0x7) || get_user(size, (u64 __user *)arg))
		return ERR_PTR(-EFAULT);
	if (size < min_size || size > BUS1_IOCTL_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	param = bus1_import_fixed_ioctl(arg, size);
	if (IS_ERR(param))
		return ERR_CAST(param);

	/* size might have changed, fix it up if it did */
	*(u64 *)param = size;
	return param;
}
