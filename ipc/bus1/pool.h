#ifndef __BUS1_POOL_H
#define __BUS1_POOL_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Pools
 *
 * Each connected peer has its own memory pool associated with the
 * file-descriptor. This pool can be mapped read-only by the client. The pool
 * is used to transfer memory from the kernel to the client; this includes
 * query/list operations the client performs, but also messages received by
 * other clients.
 *
 * The pool is managed in slices, and clients have to free each slice after
 * they are done with it.
 *
 * If a client queries the kernel for large sets of data (especially if it has
 * a non-static size), the kernel will put that data into a freshly allocated
 * slice in the pool and lets the client know the offset and size. The client
 * can then access the data directly and keep it allocated as long as it
 * wishes.
 *
 * During message transactions, a sender copies the message directly into a
 * pool-slice allocated in the pool of the receiver. There is no in-flight
 * buffer, as such, only a single copy operation is needed to transfer the
 * message.
 *
 * Note that no-one has direct write-access to pool memory. Furthermore, only
 * the owner of a pool has read-access. Any data that is written into the pool
 * is written by the kernel itself, accounted by a custom quota logic, and
 * protected by client provided policies.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/types.h>
#include "util.h"

struct file;
struct iovec;
struct kvec;

/* internal: number of bits available to slice size */
#define BUS1_POOL_SLICE_SIZE_BITS (28)
#define BUS1_POOL_SLICE_SIZE_MAX ((1 << BUS1_POOL_SLICE_SIZE_BITS) - 1)

/**
 * struct bus1_pool_slice - pool slice
 * @offset:		relative offset in parent pool
 * @size:		slice size
 * @free:		whether this slice is in-use or not
 * @ref_kernel:		whether a kernel reference exists
 * @ref_user:		whether a user reference exists
 * @entry:		link into linear list of slices
 * @rb:			link to busy/free rb-tree
 */
struct bus1_pool_slice {
	u32 offset;

	/* merge @size with flags to save 8 bytes per existing slice */
	u32 size : BUS1_POOL_SLICE_SIZE_BITS;
	u32 free : 1;
	u32 ref_kernel : 1;
	u32 ref_user : 1;

	struct list_head entry;
	struct rb_node rb;
};

/**
 * struct bus1_pool - client pool
 * @f:			backing shmem file
 * @allocated_size:	currently allocated memory in bytes
 * @slices:		all slices sorted by address
 * @slices_busy:	tree of allocated slices
 * @slices_free:	tree of free slices
 */
struct bus1_pool {
	struct file *f;
	size_t allocated_size;
	struct list_head slices;
	struct rb_root slices_busy;
	struct rb_root slices_free;
};

#define BUS1_POOL_NULL ((struct bus1_pool){})

int bus1_pool_create_internal(struct bus1_pool *pool);
void bus1_pool_destroy(struct bus1_pool *pool);

struct bus1_pool_slice *bus1_pool_alloc(struct bus1_pool *pool, size_t size);
struct bus1_pool_slice *
bus1_pool_release_kernel(struct bus1_pool *pool, struct bus1_pool_slice *slice);
void bus1_pool_publish(struct bus1_pool *pool, struct bus1_pool_slice *slice);
int bus1_pool_release_user(struct bus1_pool *pool,
			   size_t offset,
			   size_t *n_slicesp);
void bus1_pool_flush(struct bus1_pool *pool, size_t *n_slicesp);

ssize_t bus1_pool_write_iovec(struct bus1_pool *pool,
			      struct bus1_pool_slice *slice,
			      loff_t offset,
			      struct iovec *iov,
			      size_t n_iov,
			      size_t total_len);
ssize_t bus1_pool_write_kvec(struct bus1_pool *pool,
			     struct bus1_pool_slice *slice,
			     loff_t offset,
			     struct kvec *iov,
			     size_t n_iov,
			     size_t total_len);

/* see bus1_pool_create_internal() for details */
#define bus1_pool_create_for_peer(_peer) ({			\
		bus1_pool_create_internal(&(_peer)->pool);	\
	})

/**
 * bus1_pool_slice_is_public() - check whether a slice is public
 * @slice:		slice to check
 *
 * This checks whether @slice is public. That is, bus1_pool_publish() has been
 * called and the user has not released their reference, yet.
 *
 * Note that if you need reliable results, you better make sure this cannot
 * race calls to bus1_pool_publish() (or bus1_pool_release_user(),
 * respectively). IOW, keep the owning peer locked.
 *
 * Return: True if public, false if not.
 */
static inline bool bus1_pool_slice_is_public(struct bus1_pool_slice *slice)
{
	BUS1_WARN_ON(!slice->ref_kernel);
	return slice->ref_user;
}

#endif /* __BUS1_POOL_H */
