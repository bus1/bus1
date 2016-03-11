/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
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
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include "peer.h"
#include "pool.h"

/* lockdep assertion to verify the parent peer is locked */
#define bus1_pool_assert_held(_pool) \
	lockdep_assert_held(&container_of((_pool),		\
					  struct bus1_peer_info, pool)->lock)

static struct bus1_pool_slice *bus1_pool_slice_new(size_t offset, size_t size)
{
	struct bus1_pool_slice *slice;

	if (offset > U32_MAX || size == 0 || size > BUS1_POOL_SLICE_SIZE_MAX)
		return ERR_PTR(-EMSGSIZE);

	slice = kmalloc(sizeof(*slice), GFP_KERNEL);
	if (!slice)
		return ERR_PTR(-ENOMEM);

	slice->offset = offset;
	slice->size = size;

	return slice;
}

static struct bus1_pool_slice *
bus1_pool_slice_free(struct bus1_pool_slice *slice)
{
	if (!slice)
		return NULL;

	kfree(slice);

	return NULL;
}

/* insert slice into the free tree */
static void bus1_pool_slice_link_free(struct bus1_pool_slice *slice,
				      struct bus1_pool *pool)
{
	struct rb_node **n, *prev = NULL;
	struct bus1_pool_slice *ps;

	n = &pool->slices_free.rb_node;
	while (*n) {
		prev = *n;
		ps = container_of(prev, struct bus1_pool_slice, rb);
		if (slice->size < ps->size)
			n = &prev->rb_left;
		else
			n = &prev->rb_right;
	}

	rb_link_node(&slice->rb, prev, n);
	rb_insert_color(&slice->rb, &pool->slices_free);
}

/* insert slice into the busy tree */
static void bus1_pool_slice_link_busy(struct bus1_pool_slice *slice,
				      struct bus1_pool *pool)
{
	struct rb_node **n, *prev = NULL;
	struct bus1_pool_slice *ps;

	n = &pool->slices_busy.rb_node;
	while (*n) {
		prev = *n;
		ps = container_of(prev, struct bus1_pool_slice, rb);
		if (WARN_ON(slice->offset == ps->offset))
			n = &prev->rb_right; /* add anyway */
		else if (slice->offset < ps->offset)
			n = &prev->rb_left;
		else /* if (slice->offset > ps->offset) */
			n = &prev->rb_right;
	}

	rb_link_node(&slice->rb, prev, n);
	rb_insert_color(&slice->rb, &pool->slices_busy);

	pool->allocated_size += slice->size;

	WARN_ON(pool->allocated_size > pool->size);
}

/* find free slice big enough to hold @size bytes */
static struct bus1_pool_slice *
bus1_pool_slice_find_by_size(struct bus1_pool *pool, size_t size)
{
	struct bus1_pool_slice *ps, *closest = NULL;
	struct rb_node *n;

	n = pool->slices_free.rb_node;
	while (n) {
		ps = container_of(n, struct bus1_pool_slice, rb);
		if (size < ps->size) {
			closest = ps;
			n = n->rb_left;
		} else if (size > ps->size) {
			n = n->rb_right;
		} else /* if (size == ps->size) */ {
			return ps;
		}
	}

	return closest;
}

/* find used slice with given offset */
static struct bus1_pool_slice *
bus1_pool_slice_find_by_offset(struct bus1_pool *pool, size_t offset)
{
	struct bus1_pool_slice *ps;
	struct rb_node *n;

	n = pool->slices_busy.rb_node;
	while (n) {
		ps = container_of(n, struct bus1_pool_slice, rb);
		if (offset < ps->offset)
			n = n->rb_left;
		else if (offset > ps->offset)
			n = n->rb_right;
		else /* if (offset == ps->offset) */
			return ps;
	}

	return NULL;
}

/**
 * bus1_pool_create_internal() - create memory pool
 * @pool:	(uninitialized) pool to operate on
 * @size:	size of the pool
 *
 * Initialize a new pool object. This allocates a backing shmem object with the
 * given name and size.
 *
 * NOTE: All pools must be embedded into a parent bus1_peer_info object. The
 *       code works fine, if you don't, but the lockdep-annotations will fail
 *       horribly. They rely on container_of() to be valid on every pool. Use
 *       the bus1_pool_create_for_peer() macro to make sure you never violate
 *       this rule.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_pool_create_internal(struct bus1_pool *pool, size_t size)
{
	struct bus1_pool_slice *slice;
	struct page *p;
	struct file *f;
	int r;

	/* cannot calculate width of bitfields, so hardcode '4' as flag-size */
	BUILD_BUG_ON(BUS1_POOL_SLICE_SIZE_BITS + 4 > 32);
	BUILD_BUG_ON(BUS1_POOL_SIZE_MAX >=
		     (1ULL <<
		      (sizeof(((struct bus1_pool_slice *)0)->offset) * 8)));

	size = ALIGN(size, 8);
	if (size == 0 || size > BUS1_POOL_SIZE_MAX)
		return -EMSGSIZE;

	f = shmem_file_setup(KBUILD_MODNAME "-peer", size, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	r = get_write_access(file_inode(f));
	if (r < 0)
		goto error_put_file;

	slice = bus1_pool_slice_new(0, size);
	if (IS_ERR(slice)) {
		r = PTR_ERR(slice);
		goto error_put_write;
	}

	slice->free = true;
	slice->ref_kernel = false;
	slice->ref_user = false;

	pool->f = f;
	pool->size = size;
	pool->allocated_size = 0;
	INIT_LIST_HEAD(&pool->slices);
	pool->slices_free = RB_ROOT;
	pool->slices_busy = RB_ROOT;

	list_add(&slice->entry, &pool->slices);
	bus1_pool_slice_link_free(slice, pool);

	/*
	 * Touch first page of client pool so the initial allocation overhead
	 * is done during peer setup rather than a message transaction. This is
	 * really just an optimization to avoid some random peaks in common
	 * paths. It is not meant as ultimate protection.
	 */
	p = shmem_read_mapping_page(file_inode(f)->i_mapping, 0);
	if (!IS_ERR(p))
		page_cache_release(p);

	return 0;

error_put_write:
	put_write_access(file_inode(f));
error_put_file:
	fput(f);
	return r;
}

/**
 * bus1_pool_destroy() - pool to destroy
 * @pool:	pool to destroy, or NULL
 *
 * This destroys a pool that was previously create via bus1_pool_create(). If
 * NULL is passed, or if @pool->f is NULL (i.e., the pool was initialized to 0
 * but not created via bus1_pool_create(), yet), then this is a no-op.
 *
 * The caller must make sure that no kernel reference to any slice exists. Any
 * pending user-space reference to any slice is dropped by this function.
 */
void bus1_pool_destroy(struct bus1_pool *pool)
{
	struct bus1_pool_slice *slice;

	if (!pool || !pool->f)
		return;

	while ((slice = list_first_entry_or_null(&pool->slices,
						 struct bus1_pool_slice,
						 entry))) {
		WARN_ON(slice->ref_kernel);
		list_del(&slice->entry);
		bus1_pool_slice_free(slice);
	}

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
 * slice must be released via bus1_pool_release_kernel() by the caller. All
 * slices are aligned to 8 bytes (both offset and size).
 *
 * If no suitable slice can be allocated, an error is returned.
 *
 * Each pool slice can have two different references, a kernel reference and a
 * user-space reference. Initially, it only has a kernel-reference, which must
 * be dropped via bus1_pool_release_kernel(). However, if you previously
 * publish the slice via bus1_pool_publish(), it will also have a user-space
 * reference, which user-space must (indirectly) release via a call to
 * bus1_pool_release_user().
 * A slice is only actually freed if neither reference exists, anymore. Hence,
 * pool-slice can be held by both, the kernel and user-space, and both can rely
 * on it staying around as long as they wish.
 *
 * Return: Pointer to new slice, or ERR_PTR on failure.
 */
struct bus1_pool_slice *bus1_pool_alloc(struct bus1_pool *pool, size_t size)
{
	struct bus1_pool_slice *slice, *ps;
	size_t slice_size;

	bus1_pool_assert_held(pool);

	slice_size = ALIGN(size, 8);
	if (slice_size == 0 || slice_size > BUS1_POOL_SLICE_SIZE_MAX)
		return ERR_PTR(-EMSGSIZE);

	/* find smallest suitable, free slice */
	slice = bus1_pool_slice_find_by_size(pool, slice_size);
	if (!slice)
		return ERR_PTR(-EXFULL);

	/* split slice if it doesn't match exactly */
	if (slice_size < slice->size) {
		ps = bus1_pool_slice_new(slice->offset + slice_size,
					 slice->size - slice_size);
		if (IS_ERR(ps))
			return ERR_CAST(ps);

		ps->free = true;
		ps->ref_kernel = false;
		ps->ref_user = false;

		list_add(&ps->entry, &slice->entry); /* add after @slice */
		bus1_pool_slice_link_free(ps, pool);

		slice->size = slice_size;
	}

	/* move from free-tree to busy-tree */
	rb_erase(&slice->rb, &pool->slices_free);
	bus1_pool_slice_link_busy(slice, pool);

	slice->ref_kernel = true;
	slice->ref_user = false;
	slice->free = false;

	return slice;
}

static void bus1_pool_free(struct bus1_pool *pool,
			   struct bus1_pool_slice *slice)
{
	struct bus1_pool_slice *ps;

	/* don't free the slice if either has a reference */
	if (slice->ref_kernel || slice->ref_user || WARN_ON(slice->free))
		return;

	/*
	 * To release a pool-slice, we first drop it from the busy-tree, then
	 * merge it with possible previous/following free slices and re-add it
	 * to the free-tree.
	 */

	rb_erase(&slice->rb, &pool->slices_busy);

	if (!WARN_ON(slice->size > pool->allocated_size))
		pool->allocated_size -= slice->size;

	if (pool->slices.next != &slice->entry) {
		ps = container_of(slice->entry.prev, struct bus1_pool_slice,
				  entry);
		if (ps->free) {
			rb_erase(&ps->rb, &pool->slices_free);
			list_del(&slice->entry);
			ps->size += slice->size;
			bus1_pool_slice_free(slice);
			slice = ps; /* switch to previous slice */
		}
	}

	if (pool->slices.prev != &slice->entry) {
		ps = container_of(slice->entry.next, struct bus1_pool_slice,
				  entry);
		if (ps->free) {
			rb_erase(&ps->rb, &pool->slices_free);
			list_del(&ps->entry);
			slice->size += ps->size;
			bus1_pool_slice_free(ps);
		}
	}

	slice->free = true;
	bus1_pool_slice_link_free(slice, pool);
}

/**
 * bus1_pool_release_kernel() - release kernel-owned slice reference
 * @pool:	pool to free memory on
 * @slice:	slice to release
 *
 * This releases the kernel-reference to a slice that was previously allocated
 * via bus1_pool_alloc(). This only releases the kernel reference to the slice.
 * If the slice was already published to user-space, then their reference is
 * left untouched. Once both references are gone, the memory is actually freed.
 *
 * Return: NULL is returned.
 */
struct bus1_pool_slice *
bus1_pool_release_kernel(struct bus1_pool *pool, struct bus1_pool_slice *slice)
{
	if (!slice || WARN_ON(!slice->ref_kernel))
		return NULL;

	bus1_pool_assert_held(pool);

	/* kernel must own a ref to @slice */
	slice->ref_kernel = false;

	bus1_pool_free(pool, slice);

	return NULL;
}

/**
 * bus1_pool_publish() - publish a slice
 * @pool:		pool to operate on
 * @slice:		slice to publish
 *
 * Publish a pool slice to user-space, so user-space can get access to it via
 * the mapped pool memory. If the slice was already published, this is a no-op.
 * Otherwise, the slice is marked as public and will only get freed once both
 * the user-space reference *and* kernel-space reference are released.
 */
void bus1_pool_publish(struct bus1_pool *pool, struct bus1_pool_slice *slice)
{
	bus1_pool_assert_held(pool);

	/* kernel must own a ref to @slice to publish it */
	WARN_ON(!slice->ref_kernel);
	slice->ref_user = true;
}

/**
 * bus1_pool_release_user() - release a public slice
 * @pool:	pool to operate on
 * @offset:	offset of slice to release
 *
 * Release the user-space reference to a pool-slice, specified via the offset
 * of the slice. If both, the user-space reference *and* the kernel-space
 * reference to the slice are gone, the slice will be actually freed.
 *
 * If no slice exists with the given offset, or if there is no user-space
 * reference to the specified slice, an error is returned.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_pool_release_user(struct bus1_pool *pool, size_t offset)
{
	struct bus1_pool_slice *slice;

	bus1_pool_assert_held(pool);

	slice = bus1_pool_slice_find_by_offset(pool, offset);
	if (!slice || !slice->ref_user)
		return -ENXIO;

	slice->ref_user = false;
	bus1_pool_free(pool, slice);

	return 0;
}

/**
 * bus1_pool_flush() - flush all user references
 * @pool:	pool to flush
 *
 * This flushes all user-references to any slice in @pool. Kernel references
 * are left untouched.
 */
void bus1_pool_flush(struct bus1_pool *pool)
{
	struct bus1_pool_slice *slice;
	struct rb_node *node, *t;

	bus1_pool_assert_held(pool);

	for (node = rb_first(&pool->slices_busy);
	     node && ((t = rb_next(node)), true);
	     node = t) {
		slice = container_of(node, struct bus1_pool_slice, rb);
		if (!slice->ref_user)
			continue;

		/*
		 * @slice (or the logically previous/next slice) might be freed
		 * by bus1_pool_free(). However, this only ever affects 'free'
		 * slices, never busy slices. Hence, @t is protected from
		 * removal.
		 */
		slice->ref_user = false;
		bus1_pool_free(pool, slice);
	}
}

/**
 * bus1_pool_slice_copy_iovec() - copy user memory to a slice
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
	    WARN_ON(offset + total_len > slice->size))
		return -EFAULT;

	offset += slice->offset;
	iov_iter_init(&iter, WRITE, iov, n_iov, total_len);

	len = vfs_iter_write(pool->f, &iter, &offset);

	return (len >= 0 && len != total_len) ? -EFAULT : len;
}

/**
 * bus1_pool_slice_copy_kvec() - copy kernel memory to a slice
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
	    WARN_ON(offset + total_len > slice->size))
		return -EFAULT;

	offset += slice->offset;
	iov_iter_kvec(&iter, WRITE | ITER_KVEC, iov, n_iov, total_len);

	old_fs = get_fs();
	set_fs(get_ds());
	len = vfs_iter_write(pool->f, &iter, &offset);
	set_fs(old_fs);

	return (len >= 0 && len != total_len) ? -EFAULT : len;
}
