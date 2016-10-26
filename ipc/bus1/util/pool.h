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
 * A pool is a shmem-backed memory pool shared between userspace and the kernel.
 * The pool is used to transfer memory from the kernel to userspace without
 * requiring userspace to allocate the memory.
 *
 * The pool is managed in slices, which are published to userspace when they are
 * ready to be read and must be released by userspace when userspace is done
 * with them.
 *
 * Userspace has read-only access to its pools and the kernel has read-write
 * access, but published slices are not altered.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/types.h>

struct file;
struct iovec;
struct kvec;

/* internal: number of bits available to slice size */
#define BUS1_POOL_SLICE_SIZE_BITS (29)
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
 *
 * Each chunk of memory in the pool is managed as a slice. A slice can be
 * accessible by both the kernel and user-space, and their access rights are
 * managed independently. As long as the kernel has a reference to a slice, its
 * offset and size can be accessed freely and will not change. Once the kernel
 * drops its reference, it must not access the slice, anymore.
 *
 * To allow user-space access, the slice must be published. This marks the slice
 * as referenced by user-space. Note that all slices are always readable by
 * user-space, since the entire pool can be mapped. Publishing a slice only
 * marks the slice as referenced by user-space, so it will not be modified or
 * removed. Once user-space releases its reference, it should no longer access
 * the slice as it might be modified and/or overwritten by other data.
 *
 * Only if neither kernel nor user-space have a reference to a slice, the slice
 * is released. The kernel reference can only be acquired/released once, but
 * user-space references can be published/released several times. In particular,
 * if the kernel retains a reference when a slice is published and later
 * released by userspace, the same slice can be published again in the future.
 *
 * Note that both kernel-space and user-space must be aware that slice
 * references are not ref-counted. They are simple booleans. For the kernel-side
 * this is obvious, as no ref/unref functions are provided. But user-space must
 * be aware that the same slice being published several times does not increase
 * the reference count.
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
 *
 * A pool is used to allocate memory slices that can be shared between
 * kernel-space and user-space. A pool is always backed by a shmem-file and puts
 * a simple slice-allocator on top. User-space gets read-only access to the
 * entire pool, kernel-space gets read/write access via accessor-functions.
 *
 * Pools are used to transfer large sets of data to user-space, without
 * requiring a round-trip to ask user-space for a suitable memory chunk.
 * Instead, the kernel simply allocates slices in the pool and tells user-space
 * where it put the data.
 *
 * All pool operations must be serialized by the caller. No internal lock is
 * provided. Slices can be queried/modified unlocked. But any pool operation
 * (allocation, release, flush, ...) must be serialized.
 */
struct bus1_pool {
	struct file *f;
	size_t allocated_size;
	struct list_head slices;
	struct rb_root slices_busy;
	struct rb_root slices_free;
};

#define BUS1_POOL_NULL ((struct bus1_pool){})

int bus1_pool_init(struct bus1_pool *pool, const char *filename);
void bus1_pool_deinit(struct bus1_pool *pool);

struct bus1_pool_slice *bus1_pool_alloc(struct bus1_pool *pool, size_t size);
struct bus1_pool_slice *bus1_pool_release_kernel(struct bus1_pool *pool,
						 struct bus1_pool_slice *slice);
void bus1_pool_publish(struct bus1_pool *pool, struct bus1_pool_slice *slice);
int bus1_pool_release_user(struct bus1_pool *pool,
			   size_t offset,
			   size_t *n_slicesp);
void bus1_pool_flush(struct bus1_pool *pool, size_t *n_slicesp);
int bus1_pool_mmap(struct bus1_pool *pool, struct vm_area_struct *vma);

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

/**
 * bus1_pool_slice_is_public() - check whether a slice is public
 * @slice:		slice to check
 *
 * This checks whether @slice is public. That is, bus1_pool_publish() has been
 * called and the user has not released their reference, yet.
 *
 * Note that if you need reliable results, you better make sure this cannot
 * race calls to bus1_pool_publish() or bus1_pool_release_user().
 *
 * Return: True if public, false if not.
 */
static inline bool bus1_pool_slice_is_public(struct bus1_pool_slice *slice)
{
	WARN_ON(!slice->ref_kernel);
	return slice->ref_user;
}

#endif /* __BUS1_POOL_H */
