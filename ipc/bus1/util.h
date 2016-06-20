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
#include <linux/types.h>

struct dentry;
struct iovec;

int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs);
struct file *bus1_import_fd(const u32 __user *user_fd);
struct file *bus1_clone_file(struct file *file);

#if defined(CONFIG_DEBUG_FS)

struct dentry *
bus1_debugfs_create_atomic_x(const char *name,
			     umode_t mode,
			     struct dentry *parent,
			     atomic_t *value);

#else

static inline struct dentry *
bus1_debugfs_create_atomic_x(const char *name,
			     umode_t mode,
			     struct dentry *parent,
			     atomic_t *value)
{
	return ERR_PTR(-ENODEV);
}

#endif

/**
 * bus1_atomic_sub_if_ge() - subtract, if above threshold
 * @a:		atomic_t to operate on
 * @sub:	value to subtract
 * @t:		threshold
 *
 * Atomically subtract @sub from @a, if @a is greater than, or equal to, @t.
 *
 * If [t - sub] triggers an underflow, the operation is undefined. The caller
 * must verify that this cannot happen.
 *
 * Return: 1 if operation was performed, 0 if not.
 */
static inline int bus1_atomic_sub_if_ge(atomic_t *a, unsigned int sub, int t)
{
	int v, v1;

	for (v = atomic_read(a); v >= t; v = v1) {
		v1 = atomic_cmpxchg(a, v, v - sub);
		if (likely(v1 == v))
			return 1;
	}

	return 0;
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
