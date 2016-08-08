/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "user.h"
#include "util.h"

/**
 * bus1_message_new() - allocate new message
 * @n_bytes:		number of bytes to transmit
 * @n_files:		number of files to pre-allocate
 * @n_handles:		number of handles to pre-allocate
 * @peer_info:		sending peer
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
				      struct bus1_peer_info *peer_info)
{
	struct bus1_message *message;
	size_t base_size, fds_size;

	base_size = ALIGN(sizeof(*message) +
			  bus1_handle_batch_inline_size(n_handles), 8);
	fds_size = n_files * sizeof(struct file *);

	message = kmalloc(base_size + fds_size, GFP_KERNEL);
	if (!message)
		return ERR_PTR(-ENOMEM);

	message->destination = BUS1_HANDLE_INVALID;
	message->uid = -1;
	message->gid = -1;
	message->pid = 0;
	message->tid = 0;
	bus1_queue_node_init(&message->qnode, BUS1_QUEUE_NODE_MESSAGE_NORMAL,
			     (unsigned long)peer_info);
	atomic_set(&message->n_pins, 0);
	message->transaction.next = NULL;
	message->transaction.dest.handle = NULL;
	message->transaction.dest.raw_peer = NULL;
	message->user = bus1_user_ref(peer_info->user);
	message->slice = NULL;
	message->files = (void *)((u8 *)message + base_size);
	message->n_bytes = n_bytes; /* does *not* match slice->size! */
	message->n_files = n_files;
	message->n_accounted_handles = 0;
	bus1_handle_inflight_init(&message->handles, n_handles);
	memset(message->files, 0, n_files * sizeof(*message->files));

	return message;
}

/**
 * bus1_message_ref() - acquire message reference
 * @message:		message to acquire reference to, or NULL
 *
 * If non-NULL is passed, this acquires a new reference to the passed message.
 *
 * Return: @message is returned.
 */
struct bus1_message *bus1_message_ref(struct bus1_message *message)
{
	if (message)
		kref_get(&message->qnode.ref);
	return message;
}

static void bus1_message_free(struct kref *ref)
{
	struct bus1_message *message = container_of(ref, struct bus1_message,
						    qnode.ref);
	size_t i;

	BUS1_WARN_ON(message->slice);
	BUS1_WARN_ON(message->transaction.dest.raw_peer);
	BUS1_WARN_ON(message->transaction.dest.handle);
	BUS1_WARN_ON(message->transaction.next);
	BUS1_WARN_ON(atomic_read(&message->n_pins) > 0);

	for (i = 0; i < message->n_files; ++i)
		bus1_fput(message->files[i]);

	bus1_handle_inflight_destroy(&message->handles);
	bus1_queue_node_destroy(&message->qnode);
	message->user = bus1_user_unref(message->user);
	kfree_rcu(message, qnode.rcu);
}

/**
 * bus1_message_unref() - release message reference
 * @message:		message to release reference of, or NULL
 *
 * If non-NULL is passed, this releases a single reference to the passed
 * message. The caller must guarantee that the message has no resources
 * attached, anymore (by flushing it beforehand, if required).
 *
 * Return: NULL is returned.
 */
struct bus1_message *bus1_message_unref(struct bus1_message *message)
{
	if (message)
		kref_put(&message->qnode.ref, bus1_message_free);
	return NULL;
}

/**
 * bus1_message_allocate() - allocate message resources
 * @message:		message to operate on
 * @peer_info:		owning peer of the message
 *
 * Allocate a pool slice for the given message, and charge the quota of the
 * given user for all the associated in-flight resources.
 *
 * This returns the message resources pinned. Use bus1_message_unpin() to
 * realease them again.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_message_allocate(struct bus1_message *message,
			  struct bus1_peer_info *peer_info)
{
	struct bus1_pool_slice *slice;
	size_t slice_size;
	int r;

	if (BUS1_WARN_ON(atomic_read(&message->n_pins) > 0 || message->slice))
		return -ENOTRECOVERABLE;

	/* cannot overflow as all of those are limited */
	slice_size = ALIGN(message->n_bytes, 8) +
		     ALIGN(message->handles.batch.n_entries * sizeof(u64), 8) +
		     ALIGN(message->n_files + sizeof(int), 8);

	/* empty slices are forbidden, so make sure to allocate a minimum */
	slice_size = max_t(size_t, slice_size, 8);

	mutex_lock(&peer_info->lock);

	r = bus1_user_quota_charge(peer_info, message->user, slice_size,
				   message->handles.batch.n_entries,
				   message->n_files);
	if (r < 0)
		goto exit;

	slice = bus1_pool_alloc(&peer_info->pool, slice_size);
	if (IS_ERR(slice)) {
		bus1_user_quota_discharge(peer_info, message->user, slice_size,
					  message->handles.batch.n_entries,
					  message->n_files);
		r = PTR_ERR(slice);
		goto exit;
	}

	message->n_accounted_handles = message->handles.batch.n_entries;
	message->slice = slice;
	WARN_ON(atomic_inc_return(&message->n_pins) != 1);
	r = 0;

exit:
	mutex_unlock(&peer_info->lock);
	return r;
}

static void bus1_message_deallocate(struct bus1_message *message,
				    struct bus1_peer_info *peer_info)
{
	mutex_lock(&peer_info->lock);
	if (message->slice) {
		bus1_user_quota_commit(peer_info, message->user,
				       message->slice->size,
				       message->handles.batch.n_entries,
				       message->n_files);
		if (!bus1_pool_slice_is_public(message->slice))
			atomic_inc(&peer_info->user->n_slices);
		if (message->n_accounted_handles > 0)
			atomic_add(message->n_accounted_handles,
				   &peer_info->user->n_handles);
		message->slice = bus1_pool_release_kernel(&peer_info->pool,
							  message->slice);
	}
	mutex_unlock(&peer_info->lock);

	bus1_handle_inflight_flush(&message->handles, peer_info);
}

/**
 * bus1_message_pin() - pin message resources
 * @message:		message to pin, or NULL
 *
 * Pin the resources of the given message. The caller must have them already
 * pinned, this just increments the pin-counter.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @message is returned.
 */
struct bus1_message *bus1_message_pin(struct bus1_message *message)
{
	if (message)
		WARN_ON(atomic_inc_return(&message->n_pins) < 2);
	return message;
}

/**
 * bus1_message_unpin() - release pinned message resources
 * @message:		message to unpin, or NULL
 * @peer_info:		owner of the message
 *
 * This unpins the resources of the message. If this was the last pin, the
 * resources are deallocated and flushed.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_message *bus1_message_unpin(struct bus1_message *message,
					struct bus1_peer_info *peer_info)
{
	if (message && atomic_dec_and_test(&message->n_pins))
		bus1_message_deallocate(message, peer_info);
	return NULL;
}

/**
 * bus1_message_install() - install message payload into target process
 * @message:		message to operate on
 * @peer_info:		calling peer
 * @inst_fds:		whether to install FDs
 *
 * This installs the payload FDs and handles of @message into @peer_info and
 * the calling process. Handles are always installed, FDs are only installed if
 * explicitly requested via @inst_fds.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_message_install(struct bus1_message *message,
			 struct bus1_peer_info *peer_info,
			 struct bus1_cmd_recv *param)
{
	const bool inst_fds = param->flags & BUS1_RECV_FLAG_INSTALL_FDS;
	const bool peek = param->flags & BUS1_RECV_FLAG_PEEK;
	size_t n, pos, offset, n_handles = 0, n_fds = 0, n_ids = 0;
	u64 ts, *ids = NULL;
	int r, *fds = NULL;
	struct kvec vec;
	void *iter;

	lockdep_assert_held(&peer_info->lock);

	if (BUS1_WARN_ON(!message->slice))
		return -ENOTRECOVERABLE;

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

	if (message->handles.batch.n_entries > 0) {
		n_ids = min_t(size_t, message->handles.batch.n_entries,
				      BUS1_HANDLE_BATCH_SIZE);
		ids = kmalloc(n_ids * sizeof(*ids), GFP_TEMPORARY);
		if (!ids) {
			r = -ENOMEM;
			goto exit;
		}

		ts = bus1_queue_node_get_timestamp(&message->qnode);
		offset = ALIGN(message->n_bytes, 8);
		pos = 0;

		while ((n = bus1_handle_inflight_walk(&message->handles,
						peer_info, &pos, &n_handles,
						&iter, ids, ts,
						message->qnode.sender)) > 0) {
			BUS1_WARN_ON(n > n_ids);

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

	if (inst_fds && message->n_files > 0) {
		fds = kmalloc(message->n_files * sizeof(*fds), GFP_TEMPORARY);
		if (!fds) {
			r = -ENOMEM;
			goto exit;
		}

		for ( ; n_fds < message->n_files; ++n_fds) {
			r = get_unused_fd_flags(O_CLOEXEC);
			if (r < 0)
				goto exit;

			fds[n_fds] = r;
		}

		vec.iov_base = fds;
		vec.iov_len = n_fds * sizeof(int);
		offset = ALIGN(message->n_bytes, 8) +
			 ALIGN(message->handles.batch.n_entries * sizeof(u64),
			       8);

		r = bus1_pool_write_kvec(&peer_info->pool, message->slice,
					 offset, &vec, 1, vec.iov_len);
		if (r < 0)
			goto exit;
	}

	/* account handles */
	if (n_handles > 0) {
		if (!peek) {
			BUS1_WARN_ON(n_handles > message->n_accounted_handles);
			atomic_add(message->n_accounted_handles - n_handles,
				   &peer_info->user->n_handles);
			message->n_accounted_handles = 0;
			n_handles = 0;
		} else if (!bus1_atomic_sub_if_ge(&peer_info->user->n_handles,
						  n_handles, n_handles)) {
			r = -EDQUOT;
			goto exit;
		}
	}

	/* publish pool slice */
	bus1_pool_publish(&peer_info->pool, message->slice);

	/* commit handles */
	if (n_ids > 0)
		bus1_handle_inflight_commit(&message->handles, peer_info, ts,
					    message->qnode.sender);

	/* commit FDs */
	while (n_fds > 0) {
		--n_fds;
		fd_install(fds[n_fds], get_file(message->files[n_fds]));
	}

	r = 0;

exit:
	while (n_fds-- > 0)
		put_unused_fd(fds[n_fds]);
	kfree(fds);
	kfree(ids);
	return r;
}
