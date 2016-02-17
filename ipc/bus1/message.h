#ifndef __BUS1_MESSAGE_H
#define __BUS1_MESSAGE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Messages
 *
 * XXX
 */

#include <linux/fs.h>
#include <linux/kernel.h>
#include "handle.h"
#include "queue.h"

struct bus1_message;
struct bus1_peer;
struct bus1_pool_slice;
struct bus1_user;

/**
 * struct bus1_message - message
 * @qnode:		embedded queue node
 * @dd.rb:		link into multicast tree (duplicate detection)
 * @dd.destination:	destination ID (duplicate detection)
 * @transaction.next:	message list (during transactions)
 * @transaction.peer:	pinned destination (during transactions)
 * @user:		sending user
 * @slice:		actual message data
 * @files:		passed file descriptors
 * @n_files:		number of passed file descriptors
 * @handles:		passed handles
 */
struct bus1_message {
	union {
		struct {
			struct rb_node rb;
			u64 destination;
		} dd;
		struct bus1_queue_node qnode;
	};

	struct {
		struct bus1_message *next;
		struct bus1_peer *peer;
	} transaction;

	struct bus1_user *user;
	struct bus1_pool_slice *slice;
	struct file **files;
	size_t n_files;
	struct bus1_handle_inflight handles;
	/* handles must be last */
};

struct bus1_message *bus1_message_new(size_t n_files, size_t n_handles);
struct bus1_message *bus1_message_free(struct bus1_message *message);
int bus1_message_allocate_locked(struct bus1_message *message,
				 struct bus1_peer_info *peer_info,
				 struct bus1_user *user,
				 size_t slice_size);
void bus1_message_deallocate_locked(struct bus1_message *message,
				    struct bus1_peer_info *peer_info);

/**
 * bus1_message_from_node - get parent message of a queue node
 * @node:		node to get parent of
 *
 * This turns a queue node into a message. The caller must verify that the
 * passed node is actually a message.
 *
 * Return: Pointer to message is returned.
 */
static inline struct bus1_message *
bus1_message_from_node(struct bus1_queue_node *node)
{
	if (WARN_ON(!bus1_queue_node_is_message(node)))
		return NULL;

	return container_of(node, struct bus1_message, qnode);
}

#endif /* __BUS1_MESSAGE_H */
