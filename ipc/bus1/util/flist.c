/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "flist.h"

/**
 * bus1_flist_populate() - populate an flist
 * @list:		flist to operate on
 * @n:			number of elements
 * @gfp:		GFP to use for allocations
 *
 * Populate an flist. This pre-allocates the backing memory for an flist that
 * was statically initialized via bus1_flist_init(). This is NOT needed if the
 * list was allocated via bus1_flist_new().
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_flist_populate(struct bus1_flist *list, size_t n, gfp_t gfp)
{
	if (gfp & __GFP_ZERO)
		memset(list, 0, bus1_flist_inline_size(n));

	if (unlikely(n > BUS1_FLIST_BATCH)) {
		/* Never populate twice! */
		WARN_ON(list[BUS1_FLIST_BATCH].next);

		n -= BUS1_FLIST_BATCH;
		list[BUS1_FLIST_BATCH].next = bus1_flist_new(n, gfp);
		if (!list[BUS1_FLIST_BATCH].next)
			return -ENOMEM;
	}

	return 0;
}

/**
 * bus1_flist_new() - allocate new flist
 * @n:			number of elements
 * @gfp:		GFP to use for allocations
 *
 * This allocates a new flist ready to store @n elements.
 *
 * Return: Pointer to flist, NULL if out-of-memory.
 */
struct bus1_flist *bus1_flist_new(size_t n, gfp_t gfp)
{
	struct bus1_flist list, *e, *slot;
	size_t remaining;

	list.next = NULL;
	slot = &list;
	remaining = n;

	while (remaining >= BUS1_FLIST_BATCH) {
		e = kmalloc_array(sizeof(*e), BUS1_FLIST_BATCH + 1, gfp);
		if (!e)
			return bus1_flist_free(list.next, n);

		slot->next = e;
		slot = &e[BUS1_FLIST_BATCH];
		slot->next = NULL;

		remaining -= BUS1_FLIST_BATCH;
	}

	if (remaining > 0) {
		slot->next = kmalloc_array(remaining, sizeof(*e), gfp);
		if (!slot->next)
			return bus1_flist_free(list.next, n);
	}

	return list.next;
}

/**
 * bus1_flist_free() - free flist
 * @list:		flist to operate on, or NULL
 * @n:			number of elements
 *
 * This deallocates an flist previously created via bus1_flist_new().
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_flist *bus1_flist_free(struct bus1_flist *list, size_t n)
{
	struct bus1_flist *e;

	if (list) {
		/*
		 * If @list was only partially allocated, then "next" pointers
		 * might be NULL. So check @list on each iteration.
		 */
		while (list && n >= BUS1_FLIST_BATCH) {
			e = list;
			list = list[BUS1_FLIST_BATCH].next;
			kfree(e);
			n -= BUS1_FLIST_BATCH;
		}

		kfree(list);
	}

	return NULL;
}
