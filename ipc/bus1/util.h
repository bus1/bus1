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

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/uio.h>

int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs);
struct file *bus1_import_fd(const u32 __user *user_fd);
struct file *bus1_clone_file(struct file *file);

/**
 * bus1_atomic_sub_floor() - subtract, if the result is not below a given value
 * @a:		atomic_t to operate on
 * @sub:	value to subtract
 *
 * Atomically subtract @sub from @a, if the result is not less than @floor,
 * otherwise do nothing.
 *
 * The operation will *not* be performed on underflow, but the return value
 * will obviously be undefined. Hence, the caller is expected to guarantee that
 * the operation cannot underflow.
 *
 * Return: Resulting value, regardless whether it was subtracted or not.
 */
static inline int bus1_atomic_sub_unless_underflow(atomic_t *a,
						   unsigned int sub,
						   int floor)
{
	int v, v1;

	for (v = atomic_read(a); v - sub <= v && v - sub >= floor; v = v1) {
		v1 = atomic_cmpxchg(a, v, v - sub);
		if (likely(v1 == v))
			break;
	}

	return v - sub;
}

/**
 * bus1_atomic_add_unless_negative() - add value, unless already negative
 * @a:		atomic_t to operate on
 * @add:	value to add
 *
 * This atomically adds @add to @a if, and only if, @a is not negative before
 * the operation.
 *
 * Return: 1 if operation was performed, 0 if not.
 */
static inline int bus1_atomic_add_unless_negative(atomic_t *a, int add)
{
	int v, v1;

	for (v = atomic_read(a); v >= 0; v = v1) {
		v1 = atomic_cmpxchg(a, v, v + add);
		if (likely(v1 == v))
			return 1;
	}

	return 0;
}

#endif /* __BUS1_UTIL_H */
