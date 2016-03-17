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
#include <linux/slab.h>
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "user.h"

/**
 * bus1_message_new() - allocate new message
 * @n_bytes:		number of bytes to transmit
 * @n_files:		number of files to pre-allocate
 * @n_handles:		number of handles to pre-allocate
 * @silent:		is this a silent message?
 *
 * This allocates a new, unused message for free use to the caller. Storage for
 * files and handles is (partially) pre-allocated.
 *
 * Return: Pointer to new message, ERR_PTR on failure.
 */
struct bus1_message *bus1_message_new(size_t n_bytes,
				      size_t n_files,
				      size_t n_handles,
				      bool silent)
{
	struct bus1_message *message;
	size_t base_size, fds_size;

	base_size = ALIGN(sizeof(*message) +
			  bus1_handle_batch_inline_size(n_handles), 8);
	fds_size = n_files * sizeof(struct file *);

	message = kmalloc(base_size + fds_size, GFP_KERNEL);
	if (!message)
		return ERR_PTR(-ENOMEM);

	bus1_queue_node_init(&message->qnode,
			     silent ? BUS1_QUEUE_NODE_MESSAGE_SILENT :
				      BUS1_QUEUE_NODE_MESSAGE_NORMAL);
	message->data.destination = 0;
	message->data.uid = -1;
	message->data.gid = -1;
	message->data.pid = 0;
	message->data.tid = 0;
	message->data.offset = BUS1_OFFSET_INVALID;
	message->data.n_bytes = n_bytes;
	message->data.n_handles = n_handles;
	message->data.n_fds = n_files;
	message->transaction.next = NULL;
	message->transaction.handle = NULL;
	message->transaction.raw_peer = NULL;
	message->user = NULL;
	message->slice = NULL;
	message->files = (void *)((u8 *)message + base_size);
	bus1_handle_inflight_init(&message->handles, n_handles);
	memset(message->files, 0, n_files * sizeof(*message->files));

	return message;
}

/**
 * bus1_message_free() - destroy a message
 * @message:		message to destroy, or NULL
 *
 * This deallocates, destroys, and frees a message that was previously created
 * via bus1_message_new(). The caller must take care to unlink the message from
 * any queues before calling this. Furthermore, quotas must be handled before
 * as well.
 *
 * Return: NULL is returned.
 */
struct bus1_message *bus1_message_free(struct bus1_message *message)
{
	size_t i;

	if (!message)
		return NULL;

	WARN_ON(message->slice);
	WARN_ON(message->user);
	WARN_ON(message->transaction.raw_peer);
	WARN_ON(message->transaction.handle);
	WARN_ON(message->transaction.next);

	for (i = 0; i < message->data.n_fds; ++i)
		if (message->files[i])
			fput(message->files[i]);

	bus1_handle_inflight_destroy(&message->handles);
	bus1_queue_node_destroy(&message->qnode);
	kfree_rcu(message, qnode.rcu);

	return NULL;
}

/**
 * XXX
 */
int bus1_message_allocate_locked(struct bus1_message *message,
				 struct bus1_peer_info *peer_info,
				 struct bus1_user *user,
				 size_t slice_size)
{
	struct bus1_pool_slice *slice;
	int r;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(message->user || message->slice))
		return -EINVAL;

	r = bus1_user_quota_charge(peer_info, user,
				   message->data.n_bytes,
				   message->data.n_handles,
				   message->data.n_fds);
	if (r < 0)
		return r;

	slice = bus1_pool_alloc(&peer_info->pool, slice_size);
	if (IS_ERR(slice)) {
		bus1_user_quota_discharge(peer_info, user,
					  message->data.n_bytes,
					  message->data.n_handles,
					  message->data.n_fds);
		return PTR_ERR(slice);
	}

	message->user = bus1_user_ref(user);
	message->slice = slice;
	message->data.offset = slice->offset;
	return 0;
}

/**
 * XXX
 */
void bus1_message_deallocate_locked(struct bus1_message *message,
				    struct bus1_peer_info *peer_info)
{
	lockdep_assert_held(&peer_info->lock);

	if (message->slice) {
		bus1_user_quota_discharge(peer_info, message->user,
					  message->data.n_bytes,
					  message->data.n_handles,
					  message->data.n_fds);
		message->slice = bus1_pool_release_kernel(&peer_info->pool,
							  message->slice);
	}

	message->user = bus1_user_unref(message->user);
}
