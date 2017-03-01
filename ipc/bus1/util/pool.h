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

#define BUS1_POOL_SLICE_SIZE_MAX (U32_MAX)

/**
 * struct bus1_pool_slice - pool slice
 * @offset:		relative offset in parent pool
 * @size:		slice size
 * @free:		free space after slice
 * @published:		whether the slices has been published to user-space
 * @entry:		link into linear list of slices
 * @rb_offset:		link to slice rb-tree, indexed by offset
 * @rb_free:		link to slice rb-tree, indexed by free size
 * @next:		single-linked utility list
 *
 * Each chunk of memory in the pool is managed as a slice. A slice can be
 * accessible by both the kernel and user-space.
 *
 * To allow user-space access, the slice must be published. Note that all slices
 * are always readable by user-space, since the entire pool can be mapped.
 * Publishing a slice only marks the slice as such, so it will not be modified
 * or removed. Once user-space releases its reference, it should no longer
 * access the slice as it might be modified and/or overwritten by other data.
 *
 * A slice can be published and unpublished to user-space several times, but it
 * must only be released by the kernel if it is no longer published.
 *
 * Note that both kernel-space and user-space must be aware that slices are not
 * ref-counted. For the kernel-side this is obvious, as no ref/unref functions
 * are provided. But user-space must be aware that the same slice being
 * published several times does not increase the reference count.
 *
 * Each slice keeps track of the amount of free space after it in the pool, so
 * the free space can be reused in case of fragmentation.
 */
struct bus1_pool_slice {
	u32 offset;
	u32 size;
	u32 free;

	u32 allocated : 1;
	u32 published : 1;

	struct list_head entry;
	struct rb_node rb_offset;
	struct rb_node rb_free;

	struct bus1_pool_slice *next;
};

/**
 * struct bus1_pool - client pool
 * @f:			backing shmem file
 * @allocated_size:	currently allocated memory in bytes
 * @slices:		all slices sorted by address
 * @slices_offset:	tree of slices, by offset
 * @slices_free:	tree of slices, by free size
 * @root_slice:		slice tracking free space of the empty pool
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
	struct rb_root slices_offset;
	struct rb_root slices_free;
	struct bus1_pool_slice root_slice;
};

#define BUS1_POOL_NULL ((struct bus1_pool){})

int bus1_pool_init(struct bus1_pool *pool, const char *filename);
void bus1_pool_deinit(struct bus1_pool *pool);

void bus1_pool_slice_init(struct bus1_pool_slice *slice);

int bus1_pool_alloc(struct bus1_pool *pool, struct bus1_pool_slice *slice,
		    size_t size);
int bus1_pool_dealloc(struct bus1_pool *pool, struct bus1_pool_slice *slice);

void bus1_pool_publish(struct bus1_pool_slice *slice);
void bus1_pool_unpublish(struct bus1_pool_slice *slice);

struct bus1_pool_slice *
bus1_pool_slice_find_published(struct bus1_pool *pool, size_t offset);

struct bus1_pool_slice *bus1_pool_flush(struct bus1_pool *pool);

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

#endif /* __BUS1_POOL_H */
