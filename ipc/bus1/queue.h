#ifndef __BUS1_QUEUE_H
#define __BUS1_QUEUE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Message Queue
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
 *       In other words: Message transmission is not instantaneous. This is
 *       purely by choice, though. If required, transmissions could be easily
 *       made instantaneous, at the cost of shortly blocking on other
 *       conflicting tasks.
 *
 * The queue implementation uses an rb-tree (ordered by timestamps), with a
 * cached pointer to the front of the queue. The front pointer is only set if
 * the first entry in the queue is ready to be dequeued (that is, it has an
 * even timestamp). If the first entry is not ready to be dequeued, or if the
 * queue is empty, the front pointer is NULL.
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>

enum {
	BUS1_QUEUE_NODE_MESSAGE_NORMAL,
	BUS1_QUEUE_NODE_HANDLE_DESTRUCTION,
	BUS1_QUEUE_NODE_HANDLE_RELEASE,
	_BUS1_QUEUE_NODE_N,
};

/**
 * struct bus1_queue_node - node into message queue
 * @rb:				link into sorted message queue
 * @link:			link for off-queue use
 * @rcu:			rcu
 * @ref:			reference counter
 * @sender:			sender tag
 * @timestamp_and_type:		message timestamp and type of parent object
 */
struct bus1_queue_node {
	union {
		struct rb_node rb;
		struct list_head link;
		struct rcu_head rcu;
	};
	struct kref ref;
	unsigned long sender;
	u64 timestamp_and_type;
};

/**
 * struct bus1_queue - message queue
 * @clock:		local clock (used for Lamport Timestamps)
 * @front:		cached front entry
 * @waitq:		pointer to wait-queue to use for wake-ups
 * @messages:		queued messages
 * @lock:		data lock
 */
struct bus1_queue {
	u64 clock;
	struct rb_node __rcu *front;
	wait_queue_head_t *waitq;
	struct rb_root messages;
	struct mutex lock;
};

/* nodes */
void bus1_queue_node_init(struct bus1_queue_node *node,
			  unsigned int type,
			  unsigned long sender);
void bus1_queue_node_destroy(struct bus1_queue_node *node);
bool bus1_queue_node_is_queued(struct bus1_queue_node *node);
bool bus1_queue_node_is_committed(struct bus1_queue_node *node);
bool bus1_queue_node_is_staging(struct bus1_queue_node *node);
unsigned int bus1_queue_node_get_type(struct bus1_queue_node *node);
u64 bus1_queue_node_get_timestamp(struct bus1_queue_node *node);

/* queue */
void bus1_queue_init(struct bus1_queue *queue, wait_queue_head_t *waitq);
void bus1_queue_destroy(struct bus1_queue *queue);
void bus1_queue_flush(struct bus1_queue *queue, struct list_head *list);
u64 bus1_queue_stage(struct bus1_queue *queue,
		     struct bus1_queue_node *node,
		     u64 timestamp);
bool bus1_queue_commit_staged(struct bus1_queue *queue,
			      struct bus1_queue_node *node,
			      u64 timestamp);
void bus1_queue_commit_unstaged(struct bus1_queue *queue,
				struct bus1_queue_node *node);
void bus1_queue_remove(struct bus1_queue *queue, struct bus1_queue_node *node);
struct bus1_queue_node *bus1_queue_peek_locked(struct bus1_queue *queue,
					       bool *continuep);

/**
 * bus1_queue_tick() - increment queue clock
 * @queue:		queue to operate on
 *
 * This performs a clock-tick on @queue. The clock is incremented by a full
 * interval (+2). The caller is free to use both, the new value (even numbered)
 * and its predecessor (odd numbered). Both are uniquely allocated to the
 * caller.
 *
 * The caller must hold the queue lock.
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
 * The passed in timestamp must be even.
 *
 * The caller must hold the queue lock.
 *
 * Return: New clock value is returned.
 */
static inline u64 bus1_queue_sync(struct bus1_queue *queue, u64 timestamp)
{
	WARN_ON(timestamp & 1);
	queue->clock = max(queue->clock, timestamp);
	return queue->clock;
}

/**
 * bus1_queue_is_readable() - check whether a queue is readable
 * @queue:	queue to operate on
 *
 * This checks whether the given queue is readable.
 *
 * Note that messages can have 3 different states:
 *   - staging: the message is part of an active transaction
 *   - committed: the message is fully committed, but might still be blocked by
 *                a staging message
 *   - ready: the message is committed and ready to be dequeued
 *
 * This function checks that there is at least one ready or one dropped entry.
 *
 * Return: True if the queue is readable, false if not.
 */
static inline bool bus1_queue_is_readable(struct bus1_queue *queue)
{
	return rcu_access_pointer(queue->front);
}

/**
 * bus1_queue_compare() - comparator for queue ordering
 * @a_ts:		timestamp of first node to compare
 * @a_sender:		sender tag of first node to compare
 * @b_ts:		timestamp of second node to compare against
 * @b_sender:		sender tag of second node to compare against
 *
 * Messages on a message queue are ordered. This function implements the
 * comparator used for all message ordering in queues. Two tags are used for
 * ordering, the timestamp and the sender-tag of a node. Both must be passed to
 * this function.
 *
 * This compares the tuples (@a_ts, @a_sender) and (@b_ts, @b_sender).
 *
 * Return: <0 if (@a_ts, @a_sender) is ordered before, 0 if the same, >0 if
 *         ordered after.
 */
static inline int bus1_queue_compare(u64 a_ts,
				     unsigned long a_sender,
				     u64 b_ts,
				     unsigned long b_sender)
{
	/*
	 * This orders two possible queue nodes. As first-level ordering we
	 * use the timestamps, as second-level ordering we use the sender-tag.
	 *
	 * Timestamp-based ordering should be obvious. We simply make sure that
	 * any message with a lower timestamp is always considered to be first.
	 * However, due to the distributed nature of the queue-clocks, multiple
	 * messages might end up with the same timestamp. A multicast picks the
	 * highest of its destination clocks and bumps everyone else. As such,
	 * the picked timestamp for a multicast might not be unique, if another
	 * multicast with only partial destination overlap races it and happens
	 * to get the same timestamp via a distinct destination clock. If that
	 * happens, we guarantee a stable order by comparing the sender-tag of
	 * the nodes. The sender-tag can never be equal, since we allocate
	 * the unique final timestamp via the sender-clock (i.e., if the
	 * sender-tag matches, the timestamp must be distinct).
	 *
	 * Note that we strictly rely on any multicast to be staged before its
	 * final commit. This guarantees that if a node is queued with a commit
	 * timestamp, it can never be lower than the commit timestamp of any
	 * other committed node, except if it was already staged with a lower
	 * staging timestamp (as such it blocks the conflicting entry). This
	 * also implies that if two nodes share a timestamp, both will
	 * necessarily block each other until both are committed (since shared
	 * timestamps imply that an entry is guaranteed to be staged before a
	 * conflicting entry is committed).
	 */

	if (a_ts < b_ts)
		return -1;
	else if (a_ts > b_ts)
		return 1;
	else if (a_sender < b_sender)
		return -1;
	else if (a_sender > b_sender)
		return 1;

	return 0;
}

#endif /* __BUS1_QUEUE_H */
