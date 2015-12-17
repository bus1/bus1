#ifndef __BUS1_QUEUE_H
#define __BUS1_QUEUE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Message Queue
 *
 * Every peer on the bus has its own message queue. This is used to queue all
 * messages that are sent to this peer. From a user-space perspective, this
 * queue is a FIFO, that is, messages are linearly ordered by their time they
 * were sent. User-space can peek the first message, or dequeue it.
 *
 * Messages can be destined for multiple peers, hence, we need to be careful
 * that all peers get a consistent partial order of incoming messages. We
 * define the concept of `global order' to give user-space a basic set of
 * guarantees. This global order is a partial order on the set of all messages.
 * The order is defined as:
 *
 *   1) If a message B was queued *after* a message A (i.e., the send-ioctl of
 *      A returned *before* the send-ioctl for B was entered), then: A < B
 *
 *   2) If a message B was queued *after* a message A was dequeued (i.e., the
 *      recv-ioctl of A returned *before* the send-ioctl for B was entered),
 *      then: A < B
 *
 *   3) If a peer dequeues a message B *after* it dequeued a message A (i.e.,
 *      the recv-ioctl of A returned *before* the recv-ioctl for B was
 *      entered), then: A < B
 *
 *      (Note: Causality is honored. `after' and `before' do not refer to the
 *             same task, nor the same peer, but rather any kind of
 *             synchronization between the two operations.)
 *
 * The queue object implements this global order in a lockless fashion. It
 * solely relies on an atomic sequence counter on the bus object. Each message
 * to be sent gets assigned a sequence ID. Initially, this ID equals the
 * sequence counter of the bus plus 1. The sequence counter is not modified.
 * Now the message is inserted into the *sorted* queues of all its
 * destinations. After it is queued on all its destinations, the global
 * sequence counter is atomically incremented by 2, and this is also used as
 * the new sequence ID of the message. Now all queued instances of the message
 * are updated to this new ID and re-inserted into the sorted queues.
 *
 * This algorithm guarantees:
 *
 *   * The global sequence counter is always an even number, since it is only
 *     ever incremented by 2.
 *
 *   * The initial sequence number of a message is always an odd number, as it
 *     equals the even global sequence counter plus 1.
 *
 *   * The final sequence number of a message is always an even number, as it
 *     equals the even global sequence counter.
 *
 *   * The final sequence number of a message identifies it uniquely. Only odd
 *     sequence numbers can clash (since they do not imply an atomic increment)
 *     but even sequence numbers can never clash.
 *
 * With this in mind, we define that a client can only dequeue messages from
 * its queue, which have an even sequence number. Furthermore, if there is a
 * message queued with an odd sequence number that is lower than the even
 * sequence number of another message, then neither message can be dequeued.
 * They're considered to be in-flight. This guarantees that two concurrent
 * multicast messages can be queued without any locks, but either can only be
 * dequeued by a peer if their ordering has been established.
 *
 * NOTE: So far, in-flight messages is not blocked on. That is, a send-ioctl
 *       might return to user-space, but a following recv-ioctl on the
 *       destination of the message might fail with EAGAIN. That is, a message
 *       might be in-flight for an undefined amount of time.
 *
 *       In other words: Message transmission is not instanteous. Side-channels
 *                       do not order against messages.
 *
 * The queue implementation uses an rb-tree (ordered by sequence numbers), with
 * a cached pointer to the front of the queue. The front pointer is only set if
 * the first entry in the queue is ready to be dequeued (that is, it has an
 * even sequence number). If the first entry is not ready to be dequeued, or if
 * the queue is empty, the front pointer is NULL.
 *
 * The queue itself must be embedded into the parent peer structure. We do not
 * access any of the peer-data from within the queue, but we rely on the
 * peer-lock to be held by the caller (see each function for details of which
 * locks are required). Therefore, the lockdep annotations might access the
 * surrounding peer object that the queue is embedded in. See
 * bus1_queue_init_internal() for details.
 *
 * Queue entries are disconnected from a queue. Callers can allocate and free
 * them as they wish. Furthermore, the payload of the queue-entry is never
 * touched by the queue implementation (except for sanity checks in the release
 * functions). Only as soon as an entry is linked into the queue (and marked as
 * ready), other contexts may dequeue it (*and* free it!).
 * For lockless access to queue entries, we also support rcu-protected access
 * to the front of the queue. This is used in the poll() implementation right
 * now.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>

struct bus1_fs_peer;
struct bus1_pool_slice;
struct bus1_queue_entry;
struct file;

/**
 * struct bus1_queue_entry - queue entry
 * @seq:			sequence number
 * @destination_id:		destination ID used for the message
 * @transaction.next:		transaction: links all instances, or NULL
 * @transaction.fs_peer:	transaction: pins destination peer, or NULL
 * @rb:				link into the queue
 * @rcu:			rcu-head
 * @slice:			carried data, or NULL
 * @n_files:			number of carried files
 * @files:			carried files, or NULL
 */
struct bus1_queue_entry {
	u64 seq;
	u64 destination_id;
	struct {
		struct bus1_queue_entry *next;
		struct bus1_fs_peer *fs_peer;
	} transaction;
	union {
		struct rb_node rb;
		struct rcu_head rcu;
	};
	struct bus1_pool_slice *slice;
	size_t n_files;
	struct file *files[0];
};

/* turn rb_node pointer into queue entry */
#define bus1_queue_entry(_rb) \
	((_rb) ? container_of((_rb), struct bus1_queue_entry, rb) : NULL)

/**
 * struct bus1_queue - message queue
 * @messages:		queued messages
 * @front:		cached front entry
 */
struct bus1_queue {
	struct rb_root messages;
	struct rb_node __rcu *front;
};

void bus1_queue_init_internal(struct bus1_queue *queue);
void bus1_queue_destroy(struct bus1_queue *queue);
bool bus1_queue_link(struct bus1_queue *queue,
		     struct bus1_queue_entry *entry);
bool bus1_queue_unlink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry);
bool bus1_queue_relink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry,
		       u64 seq);
void bus1_queue_flush(struct bus1_queue *queue, struct bus1_pool *pool);
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue);

struct bus1_queue_entry *bus1_queue_entry_new(u64 seq, size_t n_files);
struct bus1_queue_entry *bus1_queue_entry_free(struct bus1_queue_entry *entry);
int bus1_queue_entry_install(struct bus1_queue_entry *entry,
			     struct bus1_pool *pool);

/* see bus1_queue_init_internal() for details */
#define bus1_queue_init_for_peer(_queue, _peer) ({		\
		BUILD_BUG_ON((_queue) != &(_peer)->queue);	\
		bus1_queue_init_internal(&(_peer)->queue);	\
	})

/**
 * bus1_queue_peek_rcu() - peek first available entry
 * @queue:	queue to operate on
 *
 * This returns a pointer to the first available entry in the given queue, or
 * NULL if there is none. The queue stays unmodified and the returned entry
 * remains on the queue.
 *
 * The caller must be inside an rcu read-side crictical section, and the
 * returned pointer is only valid for that critical section. Furthermore, the
 * caller must only access fields of the queue-entry that are explicitly
 * available for rcu-access.
 *
 * If the caller needs to operate on the queue entry, it better lock the peer
 * and call bus1_queue_peek(). This fast-path should only be used for poll()
 * callbacks and alike.
 *
 * Return: Pointer to first available entry, NULL if none available.
 */
static inline struct bus1_queue_entry *
bus1_queue_peek_rcu(struct bus1_queue *queue)
{
	return bus1_queue_entry(rcu_dereference(queue->front));
}

#endif /* __BUS1_QUEUE_H */
