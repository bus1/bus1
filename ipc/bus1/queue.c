/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include "peer.h"
#include "pool.h"
#include "queue.h"

/* lockdep assertion to verify the parent peer is locked */
#define bus1_queue_assert_held(_queue) \
	lockdep_assert_held(&bus1_peer_info_from_queue(_queue)->lock)
#define bus1_queue_is_held(_queue) \
	lockdep_is_held(&bus1_peer_info_from_queue(_queue)->lock)

/**
 * bus1_queue_init_internal() - initialize queue
 * @queue:	queue to initialize
 *
 * This initializes a new queue. The queue memory is considered uninitialized,
 * any previous content is lost unrecoverably.
 *
 * NOTE: All queues must be embedded into a parent bus1_peer_info object. The
 *       code works fine, if you don't, but the lockdep-annotations will fail
 *       horribly. They rely on bus1_peer_info_from_queue() to be valid on
 *       every queue. Use the bus1_queue_init_for_peer() macro to make sure you
 *       never violate this rule.
 */
void bus1_queue_init_internal(struct bus1_queue *queue)
{
	queue->messages = RB_ROOT;
	rcu_assign_pointer(queue->front, NULL);
}

/**
 * bus1_queue_destroy() - destroy queue
 * @queue:	queue to destroy
 *
 * This destroys a queue that was previously initialized via bus1_queue_init().
 * The caller must make sure the queue is empty before calling this.
 *
 * This function is a no-op, and only does safety checks on the queue. It is
 * safe to call this function multiple times on the same queue.
 *
 * The caller must guarantee that the backing memory of @queue is freed in an
 * rcu-delayed manner.
 */
void bus1_queue_destroy(struct bus1_queue *queue)
{
	WARN_ON(!RB_EMPTY_ROOT(&queue->messages));
	WARN_ON(rcu_access_pointer(queue->front));
}

/**
 * bus1_queue_link() - link entry into sorted queue
 * @queue:	queue to link into
 * @entry:	entry to link
 * @seq:	sequence number to use
 *
 * This links @entry into the message queue @queue. The caller must guarantee
 * that the entry is unlinked and was never marked as ready.
 *
 * The caller must hold the write-side peer-lock of the parent peer.
 *
 * Return: True if the queue became readable with this call.
 */
bool bus1_queue_link(struct bus1_queue *queue,
		     struct bus1_queue_entry *entry,
		     u64 seq)
{
	struct bus1_queue_entry *iter;
	struct rb_node *prev, **slot;
	bool is_leftmost = true;

	if (WARN_ON(seq == 0 ||
		    !RB_EMPTY_NODE(&entry->rb) ||
		    (entry->seq > 0 && !(entry->seq & 1))))
		return false;

	bus1_queue_assert_held(queue);

	slot = &queue->messages.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = bus1_queue_entry(prev);
		if (seq < iter->seq) {
			slot = &prev->rb_left;
		} else /* if (seq >= iter->seq) */ {
			slot = &prev->rb_right;
			is_leftmost = false;
		}
	}

	entry->seq = seq;
	rb_link_node(&entry->rb, prev, slot);
	rb_insert_color(&entry->rb, &queue->messages);

	if (is_leftmost) {
		WARN_ON(rcu_access_pointer(queue->front));
		if (!(seq & 1))
			rcu_assign_pointer(queue->front, &entry->rb);
	}

	/*
	 * If we're linked leftmost, we're the new front. If we're ready to be
	 * dequeued, the list has become readable via this entry. Note that the
	 * previous front cannot be ready in this case, as we *never* order
	 * ready entries in front of other ready entries.
	 */
	return is_leftmost && !(seq & 1);
}

/**
 * bus1_queue_unlink() - unlink entry from sorted queue
 * @queue:	queue to unlink from
 * @entry:	entry to unlink, or NULL
 *
 * This unlinks @entry from the message queue @queue. If the entry was already
 * unlinked (or NULL is passed), this is a no-op.
 *
 * The caller must hold the write-side peer-lock of the parent peer.
 *
 * Return: True if the queue became readable with this call. This can happen if
 *         you unlink a staging entry, and thus a waiting entry becomes ready.
 */
bool bus1_queue_unlink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry)
{
	struct rb_node *node;

	if (!entry || RB_EMPTY_NODE(&entry->rb))
		return false;

	node = rcu_dereference_protected(queue->front,
					 bus1_queue_is_held(queue));
	if (node == &entry->rb) {
		node = rb_next(node);
		if (node && bus1_queue_entry(node)->seq & 1)
			node = NULL;
		rcu_assign_pointer(queue->front, node);
	} else {
		node = NULL;
	}

	rb_erase(&entry->rb, &queue->messages);
	RB_CLEAR_NODE(&entry->rb);

	/*
	 * If this entry was non-ready in front, but the next entry exists and
	 * is ready, then the queue becomes readable if you pop the front.
	 */
	return (entry->seq & 1) && node && !(bus1_queue_entry(node)->seq & 1);
}

/**
 * bus1_queue_relink() - change sequence number of an entry
 * @queue:	queue to operate on
 * @entry:	entry to relink
 * @seq:	sequence number to set
 *
 * This changes the sequence number of @entry to @seq. The caller must
 * guarantee that the entry was already linked with an odd-numbered sequence
 * number. This will unlink the entry, change the sequence number and link it
 * again.
 *
 * The caller must hold the write-side peer-lock of the parent peer.
 *
 * Return: True if the queue became readable with this call.
 */
bool bus1_queue_relink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry,
		       u64 seq)
{
	struct rb_node *front;

	if (WARN_ON(seq == 0 ||
		    RB_EMPTY_NODE(&entry->rb) ||
		    !(entry->seq & 1)))
		return false;

	bus1_queue_assert_held(queue);

	/* remember front, cannot point to @entry */
	front = rcu_access_pointer(queue->front);
	WARN_ON(front == &entry->rb);

	/* drop from rb-tree and insert again */
	rb_erase(&entry->rb, &queue->messages);
	RB_CLEAR_NODE(&entry->rb);
	bus1_queue_link(queue, entry, seq);

	/* if this uncovered a front, then the queue became readable */
	return !front && rcu_access_pointer(queue->front);
}

/**
 * bus1_queue_flush() - flush all entries from a queue
 * @queue:	queue to flush
 * @pool:	pool associated with this queue
 * @peer_id:	new peer ID
 *
 * This drops all queued entries that are not targetted at @peer_id. Staging
 * entries are ignored. The caller must provide a pointer to the pool that was
 * used to allocate the slices for the stored entries.
 *
 * This call should be used after a peer reset. It flushes all old entries, but
 * leaves any new entries linked. However, note that transactions might race
 * with this call, therefore, callers must make sure to drop entries during
 * reception, in case they don't match their ID.
 *
 * Set @peer_id to 0 to flush all non-staging entries.
 *
 * The caller must hold the write-side peer-lock of the parent peer.
 */
void bus1_queue_flush(struct bus1_queue *queue,
		      struct bus1_pool *pool,
		      u64 peer_id)
{
	struct bus1_queue_entry *entry;
	struct rb_node *node, *t;

	bus1_queue_assert_held(queue);

	for (node = rb_first(&queue->messages);
	     node && ((t = rb_next(node)), true);
	     node = t) {
		entry = bus1_queue_entry(node);
		if ((entry->seq & 1) || peer_id == entry->destination_id)
			continue;

		bus1_queue_unlink(queue, entry);
		entry->slice = bus1_pool_release_kernel(pool, entry->slice);
		bus1_queue_entry_free(entry);
	}
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
 * The caller must hold the read-side peer-lock of the parent peer.
 *
 * Return: Pointer to first available entry, NULL if none available.
 */
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue)
{
	bus1_queue_assert_held(queue);

	return bus1_queue_entry(rcu_dereference_protected(queue->front,
						bus1_queue_is_held(queue)));
}

/**
 * bus1_queue_entry_new() - allocate new queue entry
 * @seq:	initial sequence number
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

	RB_CLEAR_NODE(&entry->rb);
	entry->n_files = n_files;

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
struct bus1_queue_entry *
bus1_queue_entry_free(struct bus1_queue_entry *entry)
{
	size_t i;

	if (!entry)
		return NULL;

	for (i = 0; i < entry->n_files; ++i)
		if (entry->files[i])
			fput(entry->files[i]);

	WARN_ON(entry->slice);
	WARN_ON(entry->transaction.peer);
	WARN_ON(entry->transaction.next);

	/*
	 * Entry must be unlinked by the caller. The rb-storage is re-used by
	 * the rcu-head to enforced delayed memory release. This guarantees
	 * that the entry is accessible via rcu-protected readers.
	 */
	WARN_ON(!RB_EMPTY_NODE(&entry->rb));
	kfree_rcu(entry, rcu);

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
