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
 *       In other words: Side-channels do not order against messages.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>

struct bus1_pool_slice;
struct file;

/**
 * struct bus1_queue_entry - queue entry
 * @seq:	sequence number
 * @rb:		link into the queue
 * @slice:	carried data, or NULL
 * @n_files:	number of carried files
 * @files:	carried files, or NULL
 */
struct bus1_queue_entry {
	u64 seq;
	struct rb_node rb;
	struct bus1_pool_slice *slice;
	size_t n_files;
	struct file *files[0];
};

/**
 * struct bus1_queue - message queue
 * @messages:		queued messages
 * @first:		cached first queue entry
 */
struct bus1_queue {
	struct rb_root messages;
	struct rb_node *first;
};

void bus1_queue_init(struct bus1_queue *queue);
void bus1_queue_destroy(struct bus1_queue *queue);
bool bus1_queue_link(struct bus1_queue *queue, struct bus1_queue_entry *entry);
void bus1_queue_unlink(struct bus1_queue *queue,
		       struct bus1_queue_entry *entry);
void bus1_queue_flush(struct bus1_queue *queue, struct bus1_pool *pool);
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue);

struct bus1_queue_entry *bus1_queue_entry_new(size_t n_files);
struct bus1_queue_entry *bus1_queue_entry_free(struct bus1_queue_entry *entry);
int bus1_queue_entry_install(struct bus1_queue_entry *entry,
			     struct bus1_pool *pool);

#endif /* __BUS1_QUEUE_H */
