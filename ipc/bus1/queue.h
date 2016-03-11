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
 * (You are highly encouraged to read up on 'Lamport Timestamps', the
 *  concept of 'happened-before', and 'causal ordering'. The queue
 *  implementation has its roots in Lamport Timestamps, treating a set of local
 *  CPUs as a distributed system to avoid any global synchronization.)
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
 * solely relies on a distributed clock on each peer. Each message to be sent
 * causes a clock tick on the local clock and on all destination clocks.
 * Furthermore, all clocks are synchronized, meaning they're fast-forwarded in
 * case they're behind the highest of all participating peers. No global state
 * tracking is involved.
 *
 * During a message transaction, we first queue a message as "staging" entry in
 * each destination with a preliminary timestamp. This timestamp is explicitly
 * odd numbered. Any odd numbered timestamp is considered 'staging' and causes
 * *any* message ordered after it to be blocked until it is no longer staging.
 * This allows us to queue the message in parallel with any racing multicast,
 * and be guaranteed that all possible conflicts are blocked until we
 * eventually committed a transaction.
 * To commit a transaction (after all staging entries are queued), we choose
 * the highest timestamp we have seen across all destinations and re-queue all
 * our entries on each peer. Here we use a commit timestamp (even numbered).
 *
 * With this in mind, we define that a client can only dequeue messages from
 * its queue, which have an even timestamp. Furthermore, if there is a message
 * queued with an odd timestamp that is lower than the even timestamp of
 * another message, then neither message can be dequeued. They're considered to
 * be in-flight conflicts. This guarantees that two concurrent multicast
 * messages can be queued without any *global* locks, but either can only be
 * dequeued by a peer if their ordering has been established (via commit
 * timestamps).
 *
 * NOTE: So far, in-flight messages is not blocked on. That is, a send-ioctl
 *       might return to user-space, but a following recv-ioctl on the
 *       destination of the message might fail with EAGAIN. That is, a message
 *       might be in-flight for an undefined amount of time.
 *
 *       In other words: Message transmission is not instantaneous.
 *
 * The queue implementation uses an rb-tree (ordered by timestamps), with a
 * cached pointer to the front of the queue. The front pointer is only set if
 * the first entry in the queue is ready to be dequeued (that is, it has an
 * even timestamp). If the first entry is not ready to be dequeued, or if the
 * queue is empty, the front pointer is NULL.
 *
 * The queue itself must be embedded into the parent peer structure. We do not
 * access any of the peer-data from within the queue, but we rely on the
 * peer-lock to be held by the caller (see each function for details of which
 * locks are required). Therefore, the lockdep annotations might access the
 * surrounding peer object that the queue is embedded in. See
 * bus1_queue_init_internal() for details.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>

enum {
	BUS1_QUEUE_NODE_MESSAGE_NORMAL,
	BUS1_QUEUE_NODE_MESSAGE_SILENT,
	BUS1_QUEUE_NODE_HANDLE_DESTRUCTION,
	_BUS1_QUEUE_NODE_N,
};

/**
 * struct bus1_queue - message queue
 * @messages:		queued messages
 * @front:		cached front entry
 * @n_committed:	number of committed, non-silent entries
 * @clock:		local clock (used for Lamport Timestamps)
 */
struct bus1_queue {
	struct rb_root messages;
	struct rb_node __rcu *front;
	size_t n_committed;
	u64 clock;
};

/**
 * struct bus1_queue_node - node into message queue
 * @rb:				link into sorted message queue
 * @rcu:			rcu
 * @timestamp_and_type:		message timestamp and type of parent object
 */
struct bus1_queue_node {
	union {
		struct rb_node rb;
		struct rcu_head rcu;
	};
	u64 timestamp_and_type;
};

/* queue */
void bus1_queue_init_internal(struct bus1_queue *queue);
void bus1_queue_destroy(struct bus1_queue *queue);
void bus1_queue_post_flush(struct bus1_queue *queue);
bool bus1_queue_stage(struct bus1_queue *queue,
		      struct bus1_queue_node *node,
		      u64 timestamp);
bool bus1_queue_remove(struct bus1_queue *queue,
		       struct bus1_queue_node *node);
struct bus1_queue_node *bus1_queue_peek(struct bus1_queue *queue);

/* nodes */
void bus1_queue_node_init(struct bus1_queue_node *node, unsigned int type);
void bus1_queue_node_destroy(struct bus1_queue_node *node);
bool bus1_queue_node_is_queued(struct bus1_queue_node *node);
bool bus1_queue_node_is_committed(struct bus1_queue_node *node);
unsigned int bus1_queue_node_get_type(struct bus1_queue_node *node);

/* see bus1_queue_init_internal() for details */
#define bus1_queue_init_for_peer(_peer) ({		\
		bus1_queue_init_internal(&(_peer)->queue);	\
	})

/**
 * bus1_queue_tick() - increment queue clock
 * @queue:		queue to operate on
 *
 * This performs a clock-tick on @queue. The clock is incremented by a full
 * interval (+2). The caller is free to use both, the new value (even numbered)
 * and its predecessor (odd numbered). Both are uniquely allocated to the
 * caller.
 *
 * The caller must hold the peer lock.
 *
 * Return: New clock value is returned.
 */
static inline u64 bus1_queue_tick(struct bus1_queue *queue)
{
	queue->clock += 2;
	return queue->clock;
}

/**
 * bus1_queue_sync() - sync queue clock
 * @queue:		queue to operate on
 * @timestamp:		timestamp to sync on
 *
 * This synchronizes the clock of @queue with the externally provided timestamp
 * @timestamp. That is, the queue clock is fast-forwarded to @timestamp, in
 * case it is newer than the queue clock. Otherwise, nothing is done.
 *
 * This function works with even *and* odd timestamps. It is internally
 * converted to the corresponding even timestamp, in case it is odd.
 *
 * The caller must hold the peer lock.
 *
 * Return: New clock value is returned.
 */
static inline u64 bus1_queue_sync(struct bus1_queue *queue, u64 timestamp)
{
	queue->clock = max(queue->clock, timestamp + (timestamp & 1));
	return queue->clock;
}

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
static inline struct bus1_queue_node *
bus1_queue_peek_rcu(struct bus1_queue *queue)
{
	return rb_entry_safe(rcu_dereference(queue->front),
			     struct bus1_queue_node, rb);
}

/**
 * bus1_queue_is_readable() - check whether a queue is readable
 * @queue:	queue to operate on
 *
 * This checks whether the given queue is readable. It is similar to
 * bus1_queue_peek(), but also takes in account silent messages. That is, a
 * queue is only considered readable, if it has a front entry *and* at least a
 * single non-silent, committed message.
 *
 * Note that messages can have 3 different states:
 *   - staging: the message is part of an active transaction
 *   - committed: the message is fully committed, but might still be blocked by
 *                a staging message
 *   - ready: the message is committed and ready to be dequeued.
 *
 * This function only checks that there is at least one ready entry (which
 * might be silent), and at least one committed non-silent entry. Preferably,
 * we would check whether there is at least one *ready, non-silent* entry, but
 * this would require linear queue-searches (since the transition from
 * committed to ready is not explicit).
 *
 * In other words: There might be a short race where we wake up a peer, even
 * though it can *only* dequeue silent messages. However, if that happens, we
 * guarantee that there is a non-silent message queued *AND* committed, that
 * will reach the peer as soon as the kernel is done resolving in-flight
 * dependencies. Hence, we would wake up the peer in the near future, anyway.
 *
 * Return: True if the queue is readable, false if not.
 */
static inline bool bus1_queue_is_readable(struct bus1_queue *queue)
{
	return rcu_access_pointer(queue->front) && queue->n_committed;
}

#endif /* __BUS1_QUEUE_H */
