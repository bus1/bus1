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
#include <linux/list.h>
#include <linux/slab.h>
#include "pool.h"
#include "queue.h"

/**
 * bus1_queue_init() - initialize queue
 * @queue:	queue to initialize
 *
 * This initializes a new queue. The queue memory is considered uninitialized,
 * any previous content is lost unrecoverably.
 */
void bus1_queue_init(struct bus1_queue *queue)
{
	INIT_LIST_HEAD(&queue->messages);
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
	WARN_ON(!list_empty(&queue->messages));
}

/**
 * bus1_queue_peek() - peek first entry
 * @queue:	queue to operate on
 *
 * This returns a pointer to the first entry in the given queue, or NULL if the
 * queue is empty. The queue stays unmodified and the possible first entry
 * remains on the queue.
 *
 * Return: Pointer to first entry, NULL if empty.
 */
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue)
{
	return list_first_entry_or_null(&queue->messages,
					struct bus1_queue_entry, entry);
}

/**
 * bus1_queue_push() - push entry
 * @queue:	queue to operate on
 *
 * This pushes the given, unlinked entry to the end of the queue. The caller
 * must make sure the entry is unlinked.
 */
void bus1_queue_push(struct bus1_queue *queue, struct bus1_queue_entry *entry)
{
	if (WARN_ON(!list_empty(&entry->entry)))
		return;

	list_add_tail(&entry->entry, &queue->messages);
}

/**
 * bus1_queue_pop() - pop first entry
 * @queue:	queue to operate on
 *
 * This unlinkes the first entry from the queue and returns a pointer to it. If
 * the queue is empty, this returns NULL.
 *
 * Return: Pointer to popped entry, NULL if empty.
 */
struct bus1_queue_entry *bus1_queue_pop(struct bus1_queue *queue)
{
	struct bus1_queue_entry *entry;

	entry = bus1_queue_peek(queue);
	if (entry)
		list_del_init(&entry->entry);

	return entry;
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

	entry = kzalloc(sizeof(*entry) + n_files * sizeof(struct file *),
			GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->entry);
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
	WARN_ON(!list_empty(&entry->entry));
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
