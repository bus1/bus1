/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include "pool.h"
#include "queue.h"

#define bus1_queue_entry(_rb) \
	((_rb) ? container_of((_rb), struct bus1_queue_entry, rb) : NULL)

/**
 * bus1_queue_init() - initialize queue
 * @queue:	queue to initialize
 *
 * This initializes a new queue. The queue memory is considered uninitialized,
 * any previous content is lost unrecoverably.
 */
void bus1_queue_init(struct bus1_queue *queue)
{
	queue->messages = RB_ROOT;
	queue->first = NULL;
}

/**
 * bus1_queue_destroy() - destroy queue
 * @queue:	queue to destroy
 *
 * This destroys a queue that was previously initialized via bus1_queue_init().
 * The caller must make sure the queue is empty before calling this.
 *
 * This function is a no-op, and only does safety checks on the queue.
 *
 * It is safe to call this function multiple times on the same queue.
 */
void bus1_queue_destroy(struct bus1_queue *queue)
{
	WARN_ON(queue->messages.rb_node);
	WARN_ON(queue->first);
}

/**
 * bus1_queue_link() - link entry into sorted queue
 * @queue:	queue to link into
 * @entry:	entry to link
 *
 * This links @entry into the message queue @queue. The caller must guarantee
 * that the entry is unlinked, and has a valid sequence number set.
 *
 * Return: If the queue did not have any available entries before this call,
 *         but now has, this returns true. In all other cases, false is
 *         returned.
 */
bool bus1_queue_link(struct bus1_queue *queue, struct bus1_queue_entry *entry)
{
	struct bus1_queue_entry *iter;
	struct rb_node *prev, **slot;
	bool is_leftmost = true;

	if (WARN_ON(!RB_EMPTY_NODE(&entry->rb)))
		return false;

	slot = &queue->messages.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = bus1_queue_entry(prev);
		if (entry->seq < iter->seq) {
			slot = &prev->rb_left;
		} else /* if (entry->seq >= iter->seq) */ {
			slot = &prev->rb_right;
			is_leftmost = false;
		}
	}

	rb_link_node(&entry->rb, prev, slot);
	rb_insert_color(&entry->rb, &queue->messages);

	if (is_leftmost)
		queue->first = &entry->rb;

	return is_leftmost && !(entry->seq & 1);
}

/**
 * bus1_queue_unlink() - unlink entry from sorted queue
 * @queue:	queue to unlink from
 * @entry:	entry to unlink, or NULL
 *
 * This unlinks @entry from the message queue @queue. If the entry was already
 * unlinked (or NULL is passed), this is a no-op.
 */
void bus1_queue_unlink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry)
{
	if (!entry || RB_EMPTY_NODE(&entry->rb))
		return;

	if (queue->first == &entry->rb)
		queue->first = rb_next(queue->first);

	rb_erase(&entry->rb, &queue->messages);
}

/**
 * bus1_queue_flush() - flush all entries from a queue
 * @queue:	queue to flush
 * @pool:	pool associated with this queue
 *
 * This drops all queued entries, both staging and non-staging entries. The
 * caller must provide the pool that all the slices were allocated on.
 */
void bus1_queue_flush(struct bus1_queue *queue, struct bus1_pool *pool)
{
	struct bus1_queue_entry *entry;
	struct rb_node *next;

	/*
	 * Flush all entries out of the queue. No need to keep the tree
	 * balanced, but rather just traverse it in post-order and clear each
	 * node to prevent a WARN_ON() in bus1_queue_entry_free().
	 */

	if (!queue->first)
		return;

	/* open coded: next = rb_left_deepest_node(queue->first); */
	next = queue->first;
	for (;;) {
		if (next->rb_left)
			next = next->rb_left;
		else if (next->rb_right)
			next = next->rb_right;
		else
			break;
	}

	/* post-order traversal */
	while (next) {
		entry = bus1_queue_entry(next);
		next = rb_next_postorder(next);

		RB_CLEAR_NODE(&entry->rb);
		bus1_pool_release_kernel(pool, entry->slice);
		bus1_queue_entry_free(entry);
	}

	bus1_queue_init(queue);
}

/**
 * bus1_queue_peek() - peek first available entry
 * @queue:	queue to operate on
 *
 * This returns a pointer to the first available entry in the given queue, or
 * NULL if there is none. The queue stays unmodified and the returned entry
 * remains on the queue.
 *
 * This only returns entries that are ready to be dequeued. Entries that are
 * still in staging mode will not be considered.
 *
 * Return: Pointer to first available entry, NULL if empty.
 */
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue)
{
	struct bus1_queue_entry *entry;

	entry = bus1_queue_entry(queue->first);
	return (entry && !(entry->seq & 1)) ? entry : NULL;
}

/**
 * bus1_queue_entry_new() - allocate new queue entry
 * @n_files:	number of files to carry
 *
 * This allocates a new queue-entry with pre-allocated space to carry the given
 * amount of file descriptors. The queue entry is initially unlinked and no
 * slice is associated to it. The caller is free to modify the files array and
 * the slice as they wish.
 *
 * Return: Pointer to slice, ERR_PTR on failure.
 */
struct bus1_queue_entry *bus1_queue_entry_new(size_t n_files)
{
	struct bus1_queue_entry *entry;

	entry = kmalloc(sizeof(*entry) + n_files * sizeof(struct file *),
			GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	entry->seq = 0;
	RB_CLEAR_NODE(&entry->rb);
	entry->slice = NULL;
	entry->n_files = n_files;
	if (n_files > 0)
		memset(entry->files, 0, sizeof(*entry->files) * n_files);

	return entry;
}

/**
 * bus1_queue_entry_free() - free a queue entry
 * @entry:	entry to free, or NULL
 *
 * This destroys an existing queue entry and releases all associated resources.
 * Any files that were put into entry->files are released as well.
 *
 * If NULL is passed, this is a no-op.
 *
 * The caller must make sure the queue-entry is unlinked before calling this.
 * Furthermore, the slice must be released and reset to NULL by the caller.
 *
 * Return: NULL is returned.
 */
struct bus1_queue_entry *bus1_queue_entry_free(struct bus1_queue_entry *entry)
{
	size_t i;

	if (!entry)
		return NULL;

	for (i = 0; i < entry->n_files; ++i)
		if (entry->files[i])
			fput(entry->files[i]);

	WARN_ON(entry->slice);
	WARN_ON(!RB_EMPTY_NODE(&entry->rb));
	kfree(entry);

	return NULL;
}

/**
 * bus1_queue_entry_install() - install file descriptors
 * @entry:	queue entry carrying file descriptors
 * @pool:	parent pool of the queue entry
 *
 * This installs the file-descriptors that are carried by @entry into the
 * current process. If no file-descriptors are carried, this is a no-op. If
 * anything goes wrong, an error is returned without any file-descriptor being
 * installed (i.e., this operation either installs all, or none).
 *
 * The caller must make sure the queue-entry @entry has a linked slice with
 * enough trailing space to place the file-descriptors into. Furthermore, @pool
 * must point to the pool where that slice resides in.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_queue_entry_install(struct bus1_queue_entry *entry,
			     struct bus1_pool *pool)
{
	struct kvec vec;
	size_t i, n = 0;
	int r, *fds;

	/* bail out if no files are passed or if the entry is invalid */
	if (entry->n_files == 0)
		return 0;
	if (WARN_ON(!entry->slice ||
		    entry->slice->size < entry->n_files * sizeof(*fds)))
		return -EFAULT;

	/* allocate temporary array to hold all FDs */
	fds = kmalloc_array(entry->n_files, sizeof(*fds), GFP_TEMPORARY);
	if (!fds)
		return -ENOMEM;

	/* pre-allocate unused FDs */
	for (i = 0; i < entry->n_files; ++i) {
		if (WARN_ON(!entry->files[i])) {
			fds[n++] = -1;
		} else {
			r = get_unused_fd_flags(O_CLOEXEC);
			if (r < 0)
				goto exit;

			fds[n++] = r;
		}
	}

	/* copy FD numbers into the slice */
	vec.iov_base = fds;
	vec.iov_len = n * sizeof(*fds);
	r = bus1_pool_write_kvec(pool, entry->slice,
				 entry->slice->size - n * sizeof(*fds),
				 &vec, 1, vec.iov_len);
	if (r < 0)
		goto exit;

	/* all worked out fine, now install the actual files */
	for (i = 0; i < n; ++i)
		if (fds[i] >= 0)
			fd_install(fds[i], get_file(entry->files[i]));

	r = 0;

exit:
	if (r < 0)
		for (i = 0; i < n; ++i)
			put_unused_fd(fds[i]);
	kfree(fds);
	return r;
}
