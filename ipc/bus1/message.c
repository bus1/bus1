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
 * files and handles is (partially) pre-allocated. The number of embedded
 * handles is capped, so in case many handles are passed more memory will have
 * to be allocated later.
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
	message->transaction.dest.handle = NULL;
	message->transaction.dest.raw_peer = NULL;
	message->transaction.userid = NULL;
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
 * @peer_info:		owning peer
 *
 * This deallocates, destroys, and frees a message that was previously created
 * via bus1_message_new(). The caller must take care to unlink the message from
 * any queues before calling this. Furthermore, quotas must be handled before
 * as well.
 *
 * Return: NULL is returned.
 */
struct bus1_message *bus1_message_free(struct bus1_message *message,
				       struct bus1_peer_info *peer_info)
{
	size_t i;

	if (!message)
		return NULL;

	WARN_ON(message->slice);
	WARN_ON(message->user);
	WARN_ON(message->transaction.userid);
	WARN_ON(message->transaction.dest.raw_peer);
	WARN_ON(message->transaction.dest.handle);
	WARN_ON(message->transaction.next);

	for (i = 0; i < message->data.n_fds; ++i)
		if (message->files[i])
			fput(message->files[i]);

	bus1_handle_inflight_destroy(&message->handles, peer_info);
	bus1_queue_node_destroy(&message->qnode);
	kfree_rcu(message, qnode.rcu);

	return NULL;
}

/**
 * bus1_message_allocate() - allocate pool slice for message payload
 * @message:		message to allocate slice for
 * @peer_info:		destination peer
 * @user:		user to account in-flight resources on
 *
 * Allocate a pool slice for the given message, and charge the quota of the
 * given user for all the associated in-flight resources. The peer_info lock
 * must be held by the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_message_allocate(struct bus1_message *message,
			  struct bus1_peer_info *peer_info,
			  struct bus1_user *user)
{
	struct bus1_pool_slice *slice;
	size_t slice_size;
	int r;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(message->user || message->slice))
		return -ENOTRECOVERABLE;

	r = bus1_user_quota_charge(peer_info, user,
				   message->data.n_bytes,
				   message->data.n_handles,
				   message->data.n_fds);
	if (r < 0)
		return r;

	/* cannot overflow as all of those are limited */
	slice_size = ALIGN(message->data.n_bytes, 8) +
		     ALIGN(message->data.n_handles * sizeof(u64), 8) +
		     ALIGN(message->data.n_fds + sizeof(int), 8);

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
 * bus1_message_deallocate() - deallocate pool slice for message payload
 * @message:		message to deallocate slice for
 * @peer_info:		destination peer
 *
 * If allocated, deallocate the slice for the given peer and discharge the
 * associated user quota. The peer_info lock must be held by the caller.
 */
void bus1_message_deallocate(struct bus1_message *message,
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

/**
 * bus1_message_install() - install message payload into target process
 * @message:		message to operate on
 * @peer_info:		calling peer
 *
 * This installs the payload FDs and handles of @message into @peer_info and
 * the calling process.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_message_install(struct bus1_message *message,
			 struct bus1_peer_info *peer_info)
{
	size_t n, pos, offset, n_fds = 0, n_ids = 0;
	u64 ts, *ids = NULL;
	int r, *fds = NULL;
	struct kvec vec;
	void *iter;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(!message->slice))
		return -ENOTRECOVERABLE;
	if (message->data.n_handles == 0 && message->data.n_fds == 0)
		return 0;

	/*
	 * This is carefully crafted to first allocate temporary resources that
	 * are protected from user-space access, copy them into the message
	 * slice, and only if everything succeeded, the resources are actually
	 * committed (which itself cannot fail).
	 * Hence, if anything throughout the install fails, we can revert the
	 * operation as if it never happened. The only exception is that if
	 * some other syscall tries to allocate an FD in parallel, it will skip
	 * the temporary slot we reserved.
	 */

	if (message->data.n_handles > 0) {
		n_ids = min_t(size_t, message->data.n_handles,
				      BUS1_HANDLE_BATCH_SIZE);
		ids = kmalloc(n_ids * sizeof(*ids), GFP_TEMPORARY);
		if (!ids) {
			r = -ENOMEM;
			goto exit;
		}

		ts = bus1_queue_node_get_timestamp(&message->qnode);
		offset = ALIGN(message->data.n_bytes, 8);
		pos = 0;

		while ((n = bus1_handle_inflight_walk(&message->handles,
						      peer_info, &pos, &iter,
						      ids, ts)) > 0) {
			WARN_ON(n > n_ids);

			vec.iov_base = ids;
			vec.iov_len = n * sizeof(u64);

			r = bus1_pool_write_kvec(&peer_info->pool,
						 message->slice, offset, &vec,
						 1, vec.iov_len);
			if (r < 0)
				goto exit;

			offset += n * sizeof(u64);
		}
	}

	if (message->data.n_fds > 0) {
		fds = kmalloc(message->data.n_fds * sizeof(*fds),
			      GFP_TEMPORARY);
		if (!fds) {
			r = -ENOMEM;
			goto exit;
		}

		for ( ; n_fds < message->data.n_fds; ++n_fds) {
			r = get_unused_fd_flags(O_CLOEXEC);
			if (r < 0)
				goto exit;

			fds[n_fds] = r;
		}

		vec.iov_base = fds;
		vec.iov_len = n_fds * sizeof(int);
		offset = ALIGN(message->data.n_bytes, 8) +
			 ALIGN(message->data.n_handles * sizeof(u64), 8);

		r = bus1_pool_write_kvec(&peer_info->pool, message->slice,
					 offset, &vec, 1, vec.iov_len);
		if (r < 0)
			goto exit;
	}

	/* commit handles */
	if (n_ids > 0)
		bus1_handle_inflight_commit(&message->handles, peer_info, ts);

	/* commit FDs */
	while (n_fds-- > 0)
		fd_install(fds[n_fds], get_file(message->files[n_fds]));

	r = 0;

exit:
	while (n_fds-- > 0)
		put_unused_fd(fds[n_fds]);
	kfree(fds);
	kfree(ids);
	return r;
}
