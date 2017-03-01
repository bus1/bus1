/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/aio.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include "pool.h"

/* insert slice into the free tree */
static void bus1_pool_slice_link_free(struct bus1_pool_slice *slice,
					 struct bus1_pool *pool)
{
	struct rb_node **n, *prev = NULL;
	struct bus1_pool_slice *ps;

	WARN_ON(slice->free == 0);

	n = &pool->slices_free.rb_node;
	while (*n) {
		prev = *n;
		ps = container_of(prev, struct bus1_pool_slice, rb_free);
		if (slice->free < ps->free)
			n = &prev->rb_left;
		else
			n = &prev->rb_right;
	}

	rb_link_node(&slice->rb_free, prev, n);
	rb_insert_color(&slice->rb_free, &pool->slices_free);
}

/* insert slice into the offset tree */
static void bus1_pool_slice_link_offset(struct bus1_pool_slice *slice,
					struct bus1_pool *pool)
{
	struct rb_node **n, *prev = NULL;
	struct bus1_pool_slice *ps;

	WARN_ON(slice->size == 0);

	n = &pool->slices_offset.rb_node;
	while (*n) {
		prev = *n;
		ps = container_of(prev, struct bus1_pool_slice, rb_offset);
		if (WARN_ON(slice->offset == ps->offset))
			n = &prev->rb_right; /* add anyway */
		else if (slice->offset < ps->offset)
			n = &prev->rb_left;
		else /* if (slice->offset > ps->offset) */
			n = &prev->rb_right;
	}

	rb_link_node(&slice->rb_offset, prev, n);
	rb_insert_color(&slice->rb_offset, &pool->slices_offset);

	pool->allocated_size += slice->size;
}

void bus1_pool_slice_init(struct bus1_pool_slice *slice)
{
	slice->published = false;
	slice->allocated = false;
}

static int bus1_pool_slice_link(struct bus1_pool *pool,
				struct bus1_pool_slice *slice,
				size_t offset,
				size_t size,
				size_t free,
				struct list_head *previous)
{
	if (offset > U32_MAX || size > U32_MAX || free > U32_MAX ||
	    offset + size + free > BUS1_POOL_SLICE_SIZE_MAX)
		return -EMSGSIZE;

	slice->offset = offset;
	slice->size = size;
	slice->free = free;

	/* add @slice to free tree, if necessary */
	if (slice->free > 0)
		bus1_pool_slice_link_free(slice, pool);

	/* add @slice to offset tree, if necessary */
	if (slice->size > 0)
		bus1_pool_slice_link_offset(slice, pool);

	/* add @slice after @previous */
	list_add(&slice->entry, previous);

	return 0;
}

/* find free space large enough to hold @size bytes */
static struct bus1_pool_slice *
bus1_pool_slice_find_free(struct bus1_pool *pool, size_t size)
{
	struct bus1_pool_slice *ps, *closest = NULL;
	struct rb_node *n;

	n = pool->slices_free.rb_node;
	while (n) {
		ps = container_of(n, struct bus1_pool_slice, rb_free);
		if (size < ps->free) {
			closest = ps;
			n = n->rb_left;
		} else if (size > ps->free) {
			n = n->rb_right;
		} else /* if (size == ps->free) */ {
			return ps;
		}
	}

	return closest;
}

/**
 * bus1_pool_slice_find_published() - find published slice in pool
 * @pool:	pool to operate on
 * @offset:	offset to get slice at
 *
 * Find the slice at the given offset, if it exists and is published.
 *
 * Return: the given slice on success, or NULL otherwise.
 */
struct bus1_pool_slice *
bus1_pool_slice_find_published(struct bus1_pool *pool, size_t offset)
{
	struct bus1_pool_slice *ps;
	struct rb_node *n;

	n = pool->slices_offset.rb_node;
	while (n) {
		ps = container_of(n, struct bus1_pool_slice, rb_offset);
		if (offset < ps->offset) {
			n = n->rb_left;
		} else if (offset > ps->offset) {
			n = n->rb_right;
		} else { /* if (offset == ps->offset) */
			if (ps->published)
				return ps;
			else
				return NULL;
		}
	}

	return NULL;
}

/**
 * bus1_pool_init() - create memory pool
 * @pool:	pool to operate on
 * @filename:	name to use for the shmem-file (only visible via /proc)
 *
 * Initialize a new pool object.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_pool_init(struct bus1_pool *pool, const char *filename)
{
	struct page *p;
	struct file *f;
	int r;

	BUILD_BUG_ON(BUS1_POOL_SLICE_SIZE_MAX > U32_MAX);

	f = shmem_file_setup(filename, ALIGN(BUS1_POOL_SLICE_SIZE_MAX, 8),
			     VM_NORESERVE);
	if (IS_ERR(f))
		return PTR_ERR(f);

	r = get_write_access(file_inode(f));
	if (r < 0) {
		fput(f);
		return r;
	}

	pool->f = f;
	pool->allocated_size = 0;
	INIT_LIST_HEAD(&pool->slices);
	pool->slices_free = RB_ROOT;
	pool->slices_offset = RB_ROOT;

	bus1_pool_slice_init(&pool->root_slice);
	r = bus1_pool_slice_link(pool, &pool->root_slice, 0, 0,
				 BUS1_POOL_SLICE_SIZE_MAX, &pool->slices);
	if (r < 0) {
		fput(f);
		return r;
	}

	/*
	 * Touch first page of client pool so the initial allocation overhead
	 * is done during peer setup rather than a message transaction. This is
	 * really just an optimization to avoid some random peaks in common
	 * paths. It is not meant as ultimate protection.
	 */
	p = shmem_read_mapping_page(file_inode(f)->i_mapping, 0);
	if (!IS_ERR(p))
		put_page(p);

	return 0;
}

/**
 * bus1_pool_deinit() - destroy pool
 * @pool:	pool to destroy, or NULL
 *
 * This destroys a pool that was previously create via bus1_pool_init(). The
 * caller must flush the pool before calling this. If NULL is passed, or if
 * @pool->f is NULL (i.e., the pool was initialized to 0 but not created via
 * bus1_pool_init(), yet), then this is a no-op.
 *
 * The caller must make sure that no kernel reference to any slice exists.
 */
void bus1_pool_deinit(struct bus1_pool *pool)
{
	if (!pool || !pool->f)
		return;

	WARN_ON(!list_is_singular(&pool->slices));
	WARN_ON(!RB_EMPTY_ROOT(&pool->slices_offset));
	WARN_ON(pool->slices_free.rb_node != &pool->root_slice.rb_free);
	WARN_ON(pool->root_slice.rb_free.rb_left != NULL);
	WARN_ON(pool->root_slice.rb_free.rb_right != NULL);
	WARN_ON(pool->root_slice.size != 0);
	WARN_ON(pool->root_slice.free != BUS1_POOL_SLICE_SIZE_MAX);
	WARN_ON(pool->allocated_size != 0);

	put_write_access(file_inode(pool->f));
	fput(pool->f);
	pool->f = NULL;
}

/**
 * bus1_pool_alloc() - allocate memory
 * @pool:	pool to allocate memory from
 * @size:	number of bytes to allocate
 *
 * This allocates a new slice of @size bytes from the memory pool at @pool. The
 * slice must be released via bus1_pool_dealloc() by the caller. All slices are
 * aligned to 8 bytes (both offset and size).
 *
 * If no suitable slice can be allocated, an error is returned.
 *
 * A pool slice can be published to userspace via bus1_pool_publish(), in which
 * case it it must be released via bus1_pool_unpublish() before it can be
 * deallocated.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_pool_alloc(struct bus1_pool *pool, struct bus1_pool_slice *slice,
		    size_t size)
{
	struct bus1_pool_slice *ps;
	size_t slice_size;
	int r;

	if (WARN_ON(slice->allocated))
		return -EFAULT;

	slice_size = ALIGN(size, 8);
	if (slice_size == 0 || slice_size > BUS1_POOL_SLICE_SIZE_MAX)
		return -EMSGSIZE;

	/* find slice with smallest suitable trailing free space */
	ps = bus1_pool_slice_find_free(pool, slice_size);
	if (!ps)
		return -EXFULL;

	/* add new slice in free space */
	r = bus1_pool_slice_link(pool, slice, ps->offset + ps->size, slice_size,
				 ps->free - slice_size, &ps->entry);
	if (r < 0)
		return r;

	/* remove @ps from free tree */
	rb_erase(&ps->rb_free, &pool->slices_free);
	ps->free = 0;

	slice->allocated = true;

	return 0;
}

int bus1_pool_dealloc(struct bus1_pool *pool, struct bus1_pool_slice *slice)
{
	struct bus1_pool_slice *ps;

	/* don't free the slice if it is published */
	if (WARN_ON(slice->published))
		return -EFAULT;

	/* make it a noop if the slice was never allocated */
	if (!slice->allocated)
		return 0;

	/*
	 * To release a pool-slice, we first drop it from the offset tree, and
	 * if it has free space we drop it from the free tree. Then merge it
	 * into the free space of the previous slice, before re-adding the
	 * following slice to the free tree.
	 */

	rb_erase(&slice->rb_offset, &pool->slices_offset);

	if (slice->free > 0)
		rb_erase(&slice->rb_free, &pool->slices_free);

	if (!WARN_ON(slice->size > pool->allocated_size))
		pool->allocated_size -= slice->size;

	ps = container_of(slice->entry.prev, struct bus1_pool_slice, entry);
	if (ps->free)
		rb_erase(&ps->rb_free, &pool->slices_free);
	ps->free += slice->size + slice->free;
	bus1_pool_slice_link_free(ps, pool);

	list_del(&slice->entry);

	slice->allocated = false;

	return 0;
}

/**
 * bus1_pool_publish() - publish a slice
 * @slice:		slice to publish
 *
 * Publish a pool slice to user-space, so user-space can get access to it via
 * the mapped pool memory. A slice cannot be deallocated as long as it is
 * published and a slice cannot be published more than once.
 */
void bus1_pool_publish(struct bus1_pool_slice *slice)
{
	WARN_ON(slice->published);

	slice->published = true;
}

/**
 * bus1_pool_unpublish() - unpublish a slice
 * @slice:		slice to unpublish
 *
 * Unpublish a pool slice, which was previously published to userspace. The
 * slice should no longer be accessed from userspace. If it was not currently
 * published an error is returned.
 */
void bus1_pool_unpublish(struct bus1_pool_slice *slice)
{
	WARN_ON(!slice->published);

	slice->published = false;
}

/**
 * bus1_pool_flush() - unpublish all slices
 * @pool:	pool to flush
 *
 * This unpublishes all published slices returns them to the caller.
 *
 * Return: Single-linked list of flushed entries.
 */
struct bus1_pool_slice *bus1_pool_flush(struct bus1_pool *pool)
{
	struct bus1_pool_slice *slice, *list = NULL;
	struct list_head *entry;

	list_for_each(entry, &pool->slices) {
		slice = container_of(entry, struct bus1_pool_slice, entry);

		if (!slice->published)
			continue;

		slice->published = false;

		slice->next = list;
		list = slice;
	}

	return list;
}

/**
 * bus1_pool_mmap() - mmap the pool
 * @pool:		pool to operate on
 * @vma:		VMA to map to
 *
 * This maps the pools shmem file to the provided VMA. Only read-only mappings
 * are allowed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_pool_mmap(struct bus1_pool *pool, struct vm_area_struct *vma)
{
	if (unlikely(vma->vm_flags & VM_WRITE))
		return -EPERM; /* deny write-access to the pool */

	/* replace the connection file with our shmem file */
	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = get_file(pool->f);
	vma->vm_flags &= ~VM_MAYWRITE;

	/* calls into shmem_mmap(), which simply sets vm_ops */
	return pool->f->f_op->mmap(pool->f, vma);
}

/**
 * bus1_pool_write_iovec() - copy user memory to a slice
 * @pool:		pool to operate on
 * @slice:		slice to write to
 * @offset:		relative offset into slice memory
 * @iov:		iovec array, pointing to data to copy
 * @n_iov:		number of elements in @iov
 * @total_len:		total number of bytes to copy
 *
 * This copies the memory pointed to by @iov into the memory slice @slice at
 * relative offset @offset (relative to begin of slice).
 *
 * Return: Numbers of bytes copied, negative error code on failure.
 */
ssize_t bus1_pool_write_iovec(struct bus1_pool *pool,
			      struct bus1_pool_slice *slice,
			      loff_t offset,
			      struct iovec *iov,
			      size_t n_iov,
			      size_t total_len)
{
	struct iov_iter iter;
	ssize_t len;

	if (WARN_ON(offset + total_len < offset) ||
	    WARN_ON(offset + total_len > slice->size) ||
	    WARN_ON(slice->published))
		return -EFAULT;
	if (total_len < 1)
		return 0;

	offset += slice->offset;
	iov_iter_init(&iter, WRITE, iov, n_iov, total_len);

	len = vfs_iter_write(pool->f, &iter, &offset);

	return (len >= 0 && len != total_len) ? -EFAULT : len;
}

/**
 * bus1_pool_write_kvec() - copy kernel memory to a slice
 * @pool:		pool to operate on
 * @slice:		slice to write to
 * @offset:		relative offset into slice memory
 * @iov:		kvec array, pointing to data to copy
 * @n_iov:		number of elements in @iov
 * @total_len:		total number of bytes to copy
 *
 * This copies the memory pointed to by @iov into the memory slice @slice at
 * relative offset @offset (relative to begin of slice).
 *
 * Return: Numbers of bytes copied, negative error code on failure.
 */
ssize_t bus1_pool_write_kvec(struct bus1_pool *pool,
			     struct bus1_pool_slice *slice,
			     loff_t offset,
			     struct kvec *iov,
			     size_t n_iov,
			     size_t total_len)
{
	struct iov_iter iter;
	mm_segment_t old_fs;
	ssize_t len;

	if (WARN_ON(offset + total_len < offset) ||
	    WARN_ON(offset + total_len > slice->size) ||
	    WARN_ON(slice->published))
		return -EFAULT;
	if (total_len < 1)
		return 0;

	offset += slice->offset;
	iov_iter_kvec(&iter, WRITE | ITER_KVEC, iov, n_iov, total_len);

	old_fs = get_fs();
	set_fs(get_ds());
	len = vfs_iter_write(pool->f, &iter, &offset);
	set_fs(old_fs);

	return (len >= 0 && len != total_len) ? -EFAULT : len;
}
