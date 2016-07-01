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
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include "peer.h"
#include "queue.h"

/* lockdep assertion to verify the parent peer is locked */
#define bus1_queue_assert_held(_queue)				\
	lockdep_assert_held(&container_of((_queue),		\
					  struct bus1_peer_info, queue)->qlock)
#define bus1_queue_is_held(_queue)				\
	lockdep_is_held(&container_of((_queue),			\
				      struct bus1_peer_info, queue)->qlock)

/* distinguish different node types via these masks */
#define BUS1_QUEUE_TYPE_SHIFT (62)
#define BUS1_QUEUE_TYPE_MASK (((u64)3ULL) << BUS1_QUEUE_TYPE_SHIFT)

/**
 * bus1_queue_node_get_type() - query node type
 * @node:		node to query
 *
 * This queries the node type that was provided via the node constructor. A
 * node never changes its type during its entire lifetime.
 * The caller must hold the peer qlock or own the queue-node.
 *
 * Return: Type of @node is returned.
 */
unsigned int bus1_queue_node_get_type(struct bus1_queue_node *node)
{
	return (node->timestamp_and_type & BUS1_QUEUE_TYPE_MASK) >>
							BUS1_QUEUE_TYPE_SHIFT;
}

/**
 * bus1_queue_node_get_timestamp() - query node timestamp
 * @node:		node to query
 *
 * This queries the node timestamp that is currently set on this node. The
 * caller must hold the peer qlock or own the queue-node.
 *
 * Return: Timestamp of @node is returned.
 */
u64 bus1_queue_node_get_timestamp(struct bus1_queue_node *node)
{
	return node->timestamp_and_type & ~BUS1_QUEUE_TYPE_MASK;
}

static void bus1_queue_node_set_type(struct bus1_queue_node *node, u64 type)
{
	BUILD_BUG_ON((_BUS1_QUEUE_NODE_N - 1) > (BUS1_QUEUE_TYPE_MASK >>
							BUS1_QUEUE_TYPE_SHIFT));

	WARN_ON(type & ~(BUS1_QUEUE_TYPE_MASK >> BUS1_QUEUE_TYPE_SHIFT));
	node->timestamp_and_type &= ~BUS1_QUEUE_TYPE_MASK;
	node->timestamp_and_type |= type << BUS1_QUEUE_TYPE_SHIFT;
}

static void bus1_queue_node_set_timestamp(struct bus1_queue_node *node, u64 ts)
{
	WARN_ON(ts & BUS1_QUEUE_TYPE_MASK);
	node->timestamp_and_type &= BUS1_QUEUE_TYPE_MASK;
	node->timestamp_and_type |= ts;
}

/**
 * bus1_queue_init_internal() - initialize queue
 * @queue:	queue to initialize
 *
 * This initializes a new queue. The queue memory is considered uninitialized,
 * any previous content is lost unrecoverably.
 *
 * Note that all queues must be embedded into a parent bus1_peer_info object.
 * The code works fine, if you don't, but the lockdep-annotations will fail
 * horribly. They rely on container_of() to be valid on every queue. Use the
 * bus1_queue_init_for_peer() macro to make sure you never violate this rule.
 */
void bus1_queue_init_internal(struct bus1_queue *queue,
			      wait_queue_head_t *waitq)
{
	queue->messages = RB_ROOT;
	rcu_assign_pointer(queue->front, NULL);
	queue->clock = 0;
	atomic_set(&queue->n_dropped, 0);
	queue->waitq = waitq;
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
	if (!queue)
		return;

	WARN_ON(rcu_access_pointer(queue->front));
	WARN_ON(!RB_EMPTY_ROOT(&queue->messages));
}

/**
 * bus1_queue_post_flush() - flush queue
 * @queue:		queue to flush
 *
 * To flush an entire queue, callers should lock the peer and iterate the
 * entire message tree, removing each entry without touching the tree. When
 * done, calling into bus1_queue_post_flush() will reset the tree, assuming the
 * caller completely cleared all entries.
 *
 * We cannot implement flushing inside of queue-handling, as it requires
 * knowledge about the attached payload of each message. Hence, we'd have to
 * use a callback to let the caller release each message. This is cumbersome,
 * hence we decided to force callers to traverse the tree themselves.
 */
void bus1_queue_post_flush(struct bus1_queue *queue)
{
	bus1_queue_assert_held(queue);

	queue->messages = RB_ROOT;
	rcu_assign_pointer(queue->front, NULL);
}

static int bus1_queue_node_compare(struct bus1_queue_node *a,
				   struct bus1_queue_node *b)
{
	u64 ts_a, ts_b;

	/*
	 * This compares two nodes. As first-level ordering we use the
	 * timestamps, as second-level ordering we use the sender-tag.
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

	ts_a = bus1_queue_node_get_timestamp(a);
	ts_b = bus1_queue_node_get_timestamp(b);

	if (ts_a < ts_b)
		return -1;
	else if (ts_a > ts_b)
		return 1;
	else if (a->sender < b->sender)
		return -1;
	else if (a->sender > b->sender)
		return 1;

	WARN_ON(a != b);
	return 0;
}

static void bus1_queue_add(struct bus1_queue *queue,
			   struct bus1_queue_node *node,
			   u64 timestamp)
{
	struct rb_node *front, *n, **slot;
	struct bus1_queue_node *iter;
	bool is_leftmost, readable;
	u64 ts;
	int r;

	bus1_queue_assert_held(queue);
	ts = bus1_queue_node_get_timestamp(node);
	readable = bus1_queue_is_readable(queue);

	/* provided timestamp must be valid */
	if (WARN_ON(timestamp == 0 || timestamp > queue->clock + 1))
		return;
	/* if unstamped, it must be unlinked, and vice versa */
	if (WARN_ON(!ts == !RB_EMPTY_NODE(&node->rb)))
		return;
	/* if stamped, it must be a valid staging timestamp from earlier */
	if (ts != 0 && WARN_ON(!(ts & 1) || timestamp < ts))
		return;
	/* nothing to do? */
	if (ts == timestamp)
		return;

	/*
	 * On updates, we remove our entry and re-insert it with a higher
	 * timestamp. Hence, _iff_ we were the first entry, we might uncover
	 * some new front entry. Make sure we mark it as front entry then. Note
	 * that we know that our entry must be marked staging, so it cannot be
	 * set as front, yet. If there is a front, it is some other node.
	 */
	front = rcu_dereference_protected(queue->front,
					  bus1_queue_is_held(queue));
	if (front) {
		/*
		 * If there already is a front entry, just verify that we will
		 * not order *before* it. We *must not* replace it as front.
		 */
		iter = container_of(front, struct bus1_queue_node, rb);
		WARN_ON(node == iter);
		WARN_ON(timestamp <= bus1_queue_node_get_timestamp(iter));
	} else if (!RB_EMPTY_NODE(&node->rb) && !rb_prev(&node->rb)) {
		/*
		 * We are linked into the queue as staging entry *and* we are
		 * the first entry. Now look at the following entry. If it is
		 * already committed *and* has a lower timestamp than we do, it
		 * will become the new front, so mark it as such!
		 */
		n = rb_next(&node->rb);
		if (n) {
			iter = container_of(n, struct bus1_queue_node, rb);
			if (bus1_queue_node_is_committed(iter) &&
			    bus1_queue_node_compare(iter, node) < 0)
				rcu_assign_pointer(queue->front, n);
		}
	}

	if (!RB_EMPTY_NODE(&node->rb)) {
		rb_erase(&node->rb, &queue->messages);
		/* must be staging, so no need to adjust queue->front */
	}

	bus1_queue_node_set_timestamp(node, timestamp);

	/* re-insert into sorted rb-tree with new timestamp */
	slot = &queue->messages.rb_node;
	n = NULL;
	is_leftmost = true;
	while (*slot) {
		n = *slot;
		iter = container_of(n, struct bus1_queue_node, rb);
		r = bus1_queue_node_compare(node, iter);
		if (r < 0) {
			slot = &n->rb_left;
		} else {
			slot = &n->rb_right;
			is_leftmost = false;
		}
	}

	rb_link_node(&node->rb, n, slot);
	rb_insert_color(&node->rb, &queue->messages);

	if (!(timestamp & 1)) {
		if (is_leftmost)
			rcu_assign_pointer(queue->front, &node->rb);
	}

	if (!readable && bus1_queue_is_readable(queue))
		wake_up_interruptible(queue->waitq);
}

/**
 * bus1_queue_stage() - stage queue entry with fresh timestamp
 * @queue:		queue to operate on
 * @node:		queue entry to stage
 * @timestamp:		minimum timestamp for @node
 *
 * Link a queue entry with a new timestamp. The staging entry blocks all
 * messages with timestamps synced on this queue in the future, as well as any
 * messages with a timestamp greater than @timestamp. However, it does not block
 * any messages already committed to this queue.
 *
 * The caller must provide an even timestamp and the entry may not already have
 * been committed.
 *
 * Return: The timestamp used.
 */
u64 bus1_queue_stage(struct bus1_queue *queue,
		     struct bus1_queue_node *node,
		     u64 timestamp)
{
	WARN_ON(!RB_EMPTY_NODE(&node->rb));
	WARN_ON(timestamp & 1);

	timestamp = bus1_queue_sync(queue, timestamp);
	bus1_queue_add(queue, node, timestamp + 1);

	return timestamp;
}

/**
 * bus1_queue_commit() - commit queue entry with new timestamp
 * @queue:		queue to operate on
 * @node:		queue entry to commit
 * @timestamp:		new timestamp for @node
 *
 * Link or update a queue entry according to @timestamp. If the entry was not
 * linked, yet, this will insert the entry into the queue. If it was already
 * linked, it is updated and sorted according to @timestamp.
 *
 * The caller must provide an even timestamp and the entry may not already have
 * been committed.
 *
 * Furthermore, the queue clock must be synced with the new timestamp *before*
 * staging an entry. Similarly, the timestamp of an entry can only be
 * increased, never decreased.
 */
void bus1_queue_commit(struct bus1_queue *queue,
		       struct bus1_queue_node *node,
		       u64 timestamp)
{
	WARN_ON(timestamp & 1);

	bus1_queue_add(queue, node, timestamp);
}

/**
 * bus1_queue_remove() - remove entry from queue
 * @queue:		queue to operate on
 * @node:		queue entry to remove
 *
 * This unlinks @node and fully removes it from the queue @queue. You must
 * never reuse that node again, once removed.
 *
 * If @node was still in staging, this call might uncover a new front entry and
 * as such turn the queue readable. Hence, the caller *must* handle its return
 * value.
 */
void bus1_queue_remove(struct bus1_queue *queue,
		       struct bus1_queue_node *node)
{
	struct bus1_queue_node *iter;
	struct rb_node *front, *n;
	bool readable;

	bus1_queue_assert_held(queue);

	if (!node || RB_EMPTY_NODE(&node->rb))
		return;

	readable = bus1_queue_is_readable(queue);
	front = rcu_dereference_protected(queue->front,
					  bus1_queue_is_held(queue));

	if (!rb_prev(&node->rb)) {
		/*
		 * We are the first entry in the queue. Regardless whether we
		 * are marked as front or not, our removal might uncover a new
		 * front. Hence, always look at the next following entry and
		 * see whether it is fully committed. If it is, mark it as
		 * front, but otherwise reset the front to NULL.
		 */
		n = rb_next(&node->rb);
		if (n) {
			iter = container_of(n, struct bus1_queue_node, rb);
			if (!bus1_queue_node_is_committed(iter))
				n = NULL;
		}
		rcu_assign_pointer(queue->front, n);
	}

	rb_erase(&node->rb, &queue->messages);
	RB_CLEAR_NODE(&node->rb);

	if (!readable && bus1_queue_is_readable(queue))
		wake_up_interruptible(queue->waitq);
}

void bus1_queue_drop(struct bus1_queue *queue, struct bus1_queue_node *node)
{
	bool readable;

	bus1_queue_assert_held(queue);

	bus1_queue_remove(queue, node);

	readable = bus1_queue_is_readable(queue);
	atomic_inc(&queue->n_dropped);

	if (!readable)
		wake_up_interruptible(queue->waitq);
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
 * The caller must hold the read-side peer-qlock of the parent peer.
 *
 * Return: Pointer to first available entry, NULL if none available.
 */
struct bus1_queue_node *bus1_queue_peek(struct bus1_queue *queue)
{
	struct rb_node *n;

	n = rcu_dereference_protected(queue->front,
				      bus1_queue_is_held(queue));
	return n ? container_of(n, struct bus1_queue_node, rb) : NULL;
}

/**
 * bus1_queue_node_init() - initialize queue node
 * @node:		node to initialize
 * @type:		message type
 * @sender:		sender tag
 *
 * This initializes a previously unused node, and prepares it for use with a
 * message queue.
 */
void bus1_queue_node_init(struct bus1_queue_node *node,
			  unsigned int type,
			  unsigned long sender)
{
	RB_CLEAR_NODE(&node->rb);
	node->timestamp_and_type = 0;
	bus1_queue_node_set_type(node, type);
	node->sender = sender;
}

/**
 * bus1_queue_node_destroy() - destroy queue node
 * @node:		node to destroy, or NULL
 *
 * This destroys a previously initialized queue node. This is a no-op and only
 * serves as debugger, testing whether the node was properly unqueued before.
 */
void bus1_queue_node_destroy(struct bus1_queue_node *node)
{
	WARN_ON(node && !RB_EMPTY_NODE(&node->rb));
}

/**
 * bus1_queue_node_is_queued() - check whether a node is queued
 * @node:		node to query, or NULL
 *
 * This checks whether a node is currently queued in a message queue. That is,
 * the node was linked via bus1_queue_stage() and as not been dequeued, yet
 * (both via bus1_queue_remove() or bus1_queue_flush()).
 *
 * Return: True if @node is currently queued.
 */
bool bus1_queue_node_is_queued(struct bus1_queue_node *node)
{
	return node && !RB_EMPTY_NODE(&node->rb);
}

/**
 * bus1_queue_node_is_committed() - check whether a node is committed
 * @node:		node to query, or NULL
 *
 * This checks whether a given node was already committed. In this case, the
 * queue node is owned by the queue. In all other cases, the node is usually
 * owned by an ongoing transaction or some other ongoing operation.
 *
 * Return: True if @node is committed.
 */
bool bus1_queue_node_is_committed(struct bus1_queue_node *node)
{
	u64 ts;

	ts = node ? bus1_queue_node_get_timestamp(node) : 0;
	return ts != 0 && !(ts & 1);
}
