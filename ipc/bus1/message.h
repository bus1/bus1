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
 * DOC: Messages
 *
 * XXX
 */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "queue.h"

struct bus1_message;
struct bus1_peer;
struct bus1_peer_info;
struct bus1_pool_slice;
struct bus1_user;

/**
 * struct bus1_message - message
 * @destination:		destination ID
 * @uid:			sender UID
 * @gid:			sender GID
 * @pid:			sender PID
 * @tid:			sender TID
 * @qnode:			embedded queue node
 * @transaction.next:		message list (during transactions)
 * @transaction.dest:		pinned destination (during transactions)
 * @user:			sending user
 * @slice:			actual message data
 * @files:			passed file descriptors
 * @n_bytes:			number of user-bytes transmitted
 * @n_files:			number of files transmitted
 * @handles:			passed handles
 */
struct bus1_message {
	u64 destination;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t tid;
	struct bus1_queue_node qnode;

	struct {
		struct bus1_message *next;
		struct bus1_handle_dest dest;
	} transaction;

	struct bus1_user *user;
	struct bus1_pool_slice *slice;
	struct file **files;
	size_t n_bytes;
	size_t n_files;
	struct bus1_handle_inflight handles;
	/* handles must be last */
};

struct bus1_message *bus1_message_new(size_t n_bytes,
				      size_t n_files,
				      size_t n_handles,
				      struct bus1_peer_info *peer_info);
struct bus1_message *bus1_message_ref(struct bus1_message *message);
struct bus1_message *bus1_message_unref(struct bus1_message *message);
void bus1_message_flush(struct bus1_message *message,
			struct bus1_peer_info *peer_info);
int bus1_message_allocate(struct bus1_message *message,
			  struct bus1_peer_info *peer_info);
void bus1_message_deallocate(struct bus1_message *message,
			     struct bus1_peer_info *peer_info);
int bus1_message_install(struct bus1_message *message,
			 struct bus1_peer_info *peer_info,
			 bool inst_fds);
void bus1_message_dequeue(struct bus1_message *message,
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
	unsigned int type = bus1_queue_node_get_type(node);

	if (WARN_ON(type != BUS1_QUEUE_NODE_MESSAGE_NORMAL))
		return NULL;

	return container_of(node, struct bus1_message, qnode);
}

#endif /* __BUS1_MESSAGE_H */
