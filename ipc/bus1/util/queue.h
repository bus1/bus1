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
 * A message queue is a FIFO, i.e., messages are linearly ordered by the time
 * they were sent. Moreover, atomic delivery of messages to multiple queues are
 * supported, without any global synchronization, i.e., the order of message
 * delivery is consistent across queues.
 *
 * Messages can be destined for multiple queues, hence, we need to be careful
 * that all queues get a consistent order of incoming messages. We define the
 * concept of `global order' to provide a basic set of guarantees. This global
 * order is a partial order on the set of all messages. The order is defined as:
 *
 *   1) If a message B was queued *after* a message A, then: A < B
 *
 *   2) If a message B was queued *after* a message A was dequeued, then: A < B
 *
 *   3) If a message B was dequeued *after* a message A on the same queue,
 *      then: A < B
 *
 *      (Note: Causality is honored. `after' and `before' do not refer to the
 *             same task, nor the same queue, but rather any kind of
 *             synchronization between the two operations.)
 *
 * The queue object implements this global order in a lockless fashion. It
 * solely relies on a distributed clock on each queue. Each message to be sent
 * causes a clock tick on the local clock and on all destination clocks.
 * Furthermore, all clocks are synchronized, meaning they're fast-forwarded in
 * case they're behind the highest of all participating peers. No global state
 * tracking is involved.
 *
 * During a message transaction, we first queue a message as 'staging' entry in
 * each destination with a preliminary timestamp. This timestamp is explicitly
 * odd numbered. Any odd numbered timestamp is considered 'staging' and causes
 * *any* message ordered after it to be blocked until it is no longer staging.
 * This allows us to queue the message in parallel with any racing multicast,
 * and be guaranteed that all possible conflicts are blocked until we eventually
 * commit a transaction. To commit a transaction (after all staging entries are
 * queued), we choose the highest timestamp we have seen across all destinations
 * and re-queue all our entries on each peer using that timestamp. Here we use a
 * commit timestamp (even numbered).
 *
 * With this in mind, we define that a client can only dequeue messages from
 * its queue that have an even timestamp. Furthermore, if there is a message
 * queued with an odd timestamp that is lower than the even timestamp of
 * another message, then neither message can be dequeued. They're considered to
 * be in-flight conflicts. This guarantees that two concurrent multicast
 * messages can be queued without any *global* locks, but either can only be
 * dequeued by a peer if their ordering has been established (via commit
 * timestamps).
 *
 * NOTE: A fully committed message is not guaranteed to be ready to be dequeued
 *       as it may be blocked by a staging entry. This means that there is an
 *       arbitrary (though bounded) time from a message transaction completing
 *       when the queue may still appear to be empty. In other words, message
 *       transmission is not instantaneous. It would be possible to change this
 *       at the cost of shortly blocking each message transaction on all other
 *       conflicting tasks.
 *
 * The queue implementation uses an rb-tree (ordered by timestamps and sender),
 * with a cached pointer to the front of the queue.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>

/* shift/mask for @timestamp_and_type field of queue nodes */
#define BUS1_QUEUE_TYPE_SHIFT (62)
#define BUS1_QUEUE_TYPE_MASK (((u64)3ULL) << BUS1_QUEUE_TYPE_SHIFT)
#define BUS1_QUEUE_TYPE_N (4)

/**
 * struct bus1_queue_node - node into message queue
 * @rcu:			rcu-delayed destruction
 * @rb:				link into sorted message queue
 * @timestamp_and_type:		message timestamp and type of parent object
 * @next:			single-linked utility list
 * @group:			group association
 * @owner:			node owner
 */
struct bus1_queue_node {
	union {
		struct rcu_head rcu;
		struct rb_node rb;
	};
	u64 timestamp_and_type;
	struct bus1_queue_node *next;
	void *group;
	void *owner;
};

/**
 * struct bus1_queue - message queue
 * @clock:			local clock (used for Lamport Timestamps)
 * @flush:			last flush timestamp
 * @leftmost:			cached left-most entry
 * @front:			cached front entry
 * @messages:			queued messages
 */
struct bus1_queue {
	u64 clock;
	u64 flush;
	struct rb_node *leftmost;
	struct rb_node __rcu *front;
	struct rb_root messages;
};

void bus1_queue_init(struct bus1_queue *queue);
void bus1_queue_deinit(struct bus1_queue *queue);
struct bus1_queue_node *bus1_queue_flush(struct bus1_queue *queue, u64 ts);
u64 bus1_queue_stage(struct bus1_queue *queue,
		     struct bus1_queue_node *node,
		     u64 timestamp);
void bus1_queue_commit_staged(struct bus1_queue *queue,
			      wait_queue_head_t *waitq,
			      struct bus1_queue_node *node,
			      u64 timestamp);
void bus1_queue_commit_unstaged(struct bus1_queue *queue,
				wait_queue_head_t *waitq,
				struct bus1_queue_node *node);
bool bus1_queue_commit_synthetic(struct bus1_queue *queue,
				 struct bus1_queue_node *node,
				 u64 timestamp);
void bus1_queue_remove(struct bus1_queue *queue,
		       wait_queue_head_t *waitq,
		       struct bus1_queue_node *node);
struct bus1_queue_node *bus1_queue_peek(struct bus1_queue *queue, bool *morep);

/**
 * bus1_queue_node_init() - initialize queue node
 * @node:			node to initialize
 * @type:			message type
 *
 * This initializes a previously unused node, and prepares it for use with a
 * message queue.
 */
static inline void bus1_queue_node_init(struct bus1_queue_node *node,
					unsigned int type)
{
	BUILD_BUG_ON((BUS1_QUEUE_TYPE_N - 1) > (BUS1_QUEUE_TYPE_MASK >>
						BUS1_QUEUE_TYPE_SHIFT));
	WARN_ON(type & ~(BUS1_QUEUE_TYPE_MASK >> BUS1_QUEUE_TYPE_SHIFT));

	RB_CLEAR_NODE(&node->rb);
	node->timestamp_and_type = (u64)type << BUS1_QUEUE_TYPE_SHIFT;
	node->next = NULL;
	node->group = NULL;
	node->owner = NULL;
}

/**
 * bus1_queue_node_deinit() - destroy queue node
 * @node:			node to destroy
 *
 * This destroys a previously initialized queue node. This is a no-op and only
 * serves as debugger, testing whether the node was properly unqueued before.
 */
static inline void bus1_queue_node_deinit(struct bus1_queue_node *node)
{
	WARN_ON(!RB_EMPTY_NODE(&node->rb));
	WARN_ON(node->next);
}

/**
 * bus1_queue_node_get_type() - query node type
 * @node:			node to query
 *
 * This queries the node type that was provided via the node constructor. A
 * node never changes its type during its entire lifetime.
 *
 * Return: Type of @node is returned.
 */
static inline unsigned int
bus1_queue_node_get_type(struct bus1_queue_node *node)
{
	return (node->timestamp_and_type & BUS1_QUEUE_TYPE_MASK) >>
							BUS1_QUEUE_TYPE_SHIFT;
}

/**
 * bus1_queue_node_get_timestamp() - query node timestamp
 * @node:			node to query
 *
 * This queries the node timestamp that is currently set on this node.
 *
 * Return: Timestamp of @node is returned.
 */
static inline u64 bus1_queue_node_get_timestamp(struct bus1_queue_node *node)
{
	return node->timestamp_and_type & ~BUS1_QUEUE_TYPE_MASK;
}

/**
 * bus1_queue_node_is_queued() - check whether a node is queued
 * @node:			node to query
 *
 * This checks whether a node is currently queued in a message queue. That is,
 * the node was linked and has not been dequeued, yet.
 *
 * Return: True if @node is currently queued.
 */
static inline bool bus1_queue_node_is_queued(struct bus1_queue_node *node)
{
	return !RB_EMPTY_NODE(&node->rb);
}

/**
 * bus1_queue_node_is_staging() - check whether a node is marked staging
 * @node:			node to query
 *
 * This checks whether a given node is queued, but still marked staging. That
 * means, the node has been put on the queue but there is still a transaction
 * that pins it to commit it later.
 *
 * Return: True if @node is queued as staging entry.
 */
static inline bool bus1_queue_node_is_staging(struct bus1_queue_node *node)
{
	return bus1_queue_node_get_timestamp(node) & 1;
}

/**
 * bus1_queue_tick() - increment queue clock
 * @queue:			queue to operate on
 *
 * This performs a clock-tick on @queue. The clock is incremented by a full
 * interval (+2). The caller is free to use both, the new value (even numbered)
 * and its successor (odd numbered). Both are uniquely allocated to the
 * caller.
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
 * @queue:			queue to operate on
 * @timestamp:			timestamp to sync on
 *
 * This synchronizes the clock of @queue with the externally provided timestamp
 * @timestamp. That is, the queue clock is fast-forwarded to @timestamp, in
 * case it is newer than the queue clock. Otherwise, nothing is done.
 *
 * The passed in timestamp must be even.
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
 * bus1_queue_is_readable_rcu() - check whether a queue is readable
 * @queue:			queue to operate on
 *
 * This checks whether the given queue is readable.
 *
 * This does not require any locking, except for an rcu-read-side critical
 * section.
 *
 * Return: True if the queue is readable, false if not.
 */
static inline bool bus1_queue_is_readable_rcu(struct bus1_queue *queue)
{
	return rcu_access_pointer(queue->front);
}

/**
 * bus1_queue_compare() - comparator for queue ordering
 * @a_ts:			timestamp of first node to compare
 * @a_g:			group of first node to compare
 * @b_ts:			timestamp of second node to compare against
 * @b_g:			group of second node to compare against
 *
 * Messages on a message queue are ordered. This function implements the
 * comparator used for all message ordering in queues. Two tags are used for
 * ordering, the timestamp and the group-tag of a node. Both must be passed to
 * this function.
 *
 * This compares the tuples (@a_ts, @a_g) and (@b_ts, @b_g).
 *
 * Return: <0 if (@a_ts, @a_g) is ordered before, >0 if after, 0 if same.
 */
static inline int bus1_queue_compare(u64 a_ts, void *a_g, u64 b_ts, void *b_g)
{
	/*
	 * This orders two possible queue nodes. As first-level ordering we
	 * use the timestamps, as second-level ordering we use the group-tag.
	 *
	 * Timestamp-based ordering should be obvious. We simply make sure that
	 * any message with a lower timestamp is always considered to be first.
	 * However, due to the distributed nature of the queue-clocks, multiple
	 * messages might end up with the same timestamp. A multicast picks the
	 * highest of its destination clocks and bumps everyone else. As such,
	 * the picked timestamp for a multicast might not be unique, if another
	 * multicast with only partial destination overlap races it and happens
	 * to get the same timestamp via a distinct destination clock. If that
	 * happens, we guarantee a stable order by comparing the group-tag of
	 * the nodes. The group-tag is only ever equal if both messages belong
	 * to the same transaction.
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
	else if (a_g < b_g)
		return -1;
	else if (a_g > b_g)
		return 1;

	return 0;
}

#endif /* __BUS1_QUEUE_H */
