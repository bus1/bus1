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

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/uio.h>

int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs);
struct file *bus1_import_fd(const u32 __user *user_fd);
struct file *bus1_clone_file(struct file *file);

/*
 * bus1_atomic_sub_floor() - subtract, if the result is non-negative
 * @a:		an atomic
 * @sub:	the value to subtract
 *
 * Atomically subtract @sub from @a, if the result is non-negative, otherwise
 * do nothing.
 *
 * Return: the result if the operation succeeded, and a negative value
 * otherwise.
 */
static inline int bus1_atomic_sub_floor(atomic_t *a, int sub) {
	int v, v1;

	for (v = atomic_read(a); v - sub >= 0; v = v1) {
		v1 = atomic_cmpxchg(a, v, v - sub);
		if (likely(v1 == v))
			return v - sub;
	}

	return -ERANGE;
}

#endif /* __BUS1_UTIL_H */
