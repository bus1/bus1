#ifndef __BUS1_FLIST_H
#define __BUS1_FLIST_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Fixed Lists
 *
 * This implements a fixed-size list called bus1_flist. The size of the list
 * must be constant over the lifetime of the list. The list can hold one
 * arbitrary pointer per node.
 *
 * Fixed lists are a combination of a linked list and a static array. That is,
 * fixed lists behave like linked lists (no random access, but arbitrary size),
 * but compare in speed with arrays (consecutive accesses are fast). Unlike
 * fixed arrays, fixed lists can hold huge number of elements without requiring
 * vmalloc(), but solely relying on small-size kmalloc() allocations.
 *
 * Internally, fixed lists are a singly-linked list of static arrays. This
 * guarantees that iterations behave almost like on an array, except when
 * crossing a batch-border.
 *
 * Fixed lists can replace fixed-size arrays whenever you need to support large
 * number of elements, but don't need random access. Fixed lists have ALMOST
 * the same memory requirements as fixed-size arrays, except one pointer of
 * state per 'BUS1_FLIST_BATCH' elements. If only a small size (i.e., it only
 * requires one batch) is stored in a fixed list, then its memory requirements
 * and iteration time are equivalent to fixed-size arrays.
 */

#include <linux/kernel.h>

#define BUS1_FLIST_BATCH (1024)

/**
 * struct bus1_flist - fixed list
 * @next:		pointer to next batch
 * @ptr:		stored entry
 */
struct bus1_flist {
	union {
		struct bus1_flist *next;
		void *ptr;
	};
};

int bus1_flist_populate(struct bus1_flist *flist, size_t n, gfp_t gfp);
struct bus1_flist *bus1_flist_new(size_t n, gfp_t gfp);
struct bus1_flist *bus1_flist_free(struct bus1_flist *list, size_t n);

/**
 * bus1_flist_inline_size() - calculate required inline size
 * @n:			number of entries
 *
 * When allocating storage for an flist, this calculates the size of the
 * initial array in bytes. Use bus1_flist_new() directly if you want to
 * allocate an flist on the heap. This helper is only needed if you embed an
 * flist into another struct like this:
 *
 *     struct foo {
 *             ...
 *             struct bus1_flist list[];
 *     };
 *
 * In that case the flist must be the last element, and the size in bytes
 * required by it is returned by this function.
 *
 * The inline-size of an flist is always bound to a fixed maximum. That is,
 * regardless of @n, this will always return a reasonable number that can be
 * allocated via kmalloc().
 *
 * Return: Size in bytes required for the initial batch of an flist.
 */
static inline size_t bus1_flist_inline_size(size_t n)
{
	return sizeof(struct bus1_flist) *
		((likely(n < BUS1_FLIST_BATCH)) ? n : (BUS1_FLIST_BATCH + 1));
}

/**
 * bus1_flist_init() - initialize an flist
 * @list:		flist to initialize
 * @n:			number of entries
 *
 * This initializes an flist of size @n. It does NOT preallocate the memory,
 * but only initializes @list in a way that bus1_flist_deinit() can be called
 * on it. Use bus1_flist_populate() to populate the flist.
 *
 * This is only needed if your backing memory of @list is shared with another
 * object. If possible, use bus1_flist_new() to allocate an flist on the heap
 * and avoid this dance.
 */
static inline void bus1_flist_init(struct bus1_flist *list, size_t n)
{
	BUILD_BUG_ON(sizeof(struct bus1_flist) != sizeof(void *));

	if (unlikely(n >= BUS1_FLIST_BATCH))
		list[BUS1_FLIST_BATCH].next = NULL;
}

/**
 * bus1_flist_deinit() - deinitialize an flist
 * @list:		flist to deinitialize
 * @n:			number of entries
 *
 * This deallocates an flist and releases all resources. If already
 * deinitialized, this is a no-op. This is only needed if you called
 * bus1_flist_populate().
 */
static inline void bus1_flist_deinit(struct bus1_flist *list, size_t n)
{
	if (unlikely(n >= BUS1_FLIST_BATCH)) {
		bus1_flist_free(list[BUS1_FLIST_BATCH].next,
				n - BUS1_FLIST_BATCH);
		list[BUS1_FLIST_BATCH].next = NULL;
	}
}

/**
 * bus1_flist_next() - flist iterator
 * @iter:		iterator
 * @pos:		current position
 *
 * This advances an flist iterator by one position. @iter must point to the
 * current position, and the new position is returned by this function. @pos
 * must point to a variable that contains the current index position. That is,
 * @pos must be initialized to 0 and @iter to the flist head.
 *
 * Neither @pos nor @iter must be modified by anyone but this helper. In the
 * loop body you can use @iter->ptr to access the current element.
 *
 * This iterator is normally used like this:
 *
 *     size_t pos, n = 128;
 *     struct bus1_flist *e, *list = bus1_flist_new(n);
 *
 *     ...
 *
 *     for (pos = 0, e = list; pos < n; e = bus1_flist_next(e, &pos)) {
 *             ... access e->ptr ...
 *     }
 *
 * Return: Next iterator position.
 */
static inline struct bus1_flist *bus1_flist_next(struct bus1_flist *iter,
						 size_t *pos)
{
	return (++*pos % BUS1_FLIST_BATCH) ? (iter + 1) : (iter + 1)->next;
}

/**
 * bus1_flist_walk() - walk flist in batches
 * @list:		list to walk
 * @n:			number of entries
 * @iter:		iterator
 * @pos:		current position
 *
 * This walks an flist in batches of size up to BUS1_FLIST_BATCH. It is
 * normally used like this:
 *
 *     size_t pos, z, n = 65536;
 *     struct bus1_flist *e, *list = bus1_flist_new(n);
 *
 *     ...
 *
 *     pos = 0;
 *     while ((z = bus1_flist_walk(list, n, &e, &pos)) > 0) {
 *             ... access e[0...z]->ptr
 *             ... invariant: z <= BUS1_FLIST_BATCH
 *             ... invariant: e[i]->ptr == (&e->ptr)[i]
 *     }
 *
 * Return: Size of batch at @iter.
 */
static inline size_t bus1_flist_walk(struct bus1_flist *list,
				     size_t n,
				     struct bus1_flist **iter,
				     size_t *pos)
{
	if (*pos < n) {
		n = n - *pos;
		if (unlikely(n > BUS1_FLIST_BATCH))
			n = BUS1_FLIST_BATCH;
		if (likely(*pos == 0))
			*iter = list;
		else
			*iter = (*iter)[BUS1_FLIST_BATCH].next;
		*pos += n;
	} else {
		n = 0;
	}
	return n;
}

#endif /* __BUS1_FLIST_H */
