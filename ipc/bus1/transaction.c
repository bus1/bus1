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
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "user.h"
#include "util.h"

struct bus1_transaction {
	/* sender context */
	struct bus1_peer *peer;
	struct bus1_peer_info *peer_info;
	struct bus1_cmd_send *param;
	const struct cred *cred;
	struct pid *pid;
	struct pid *tid;

	/* payload */
	struct iovec *vecs;
	struct file **files;

	/* transaction state */
	size_t length_vecs;
	struct bus1_message *entries;
	struct bus1_handle_transfer handles;
	/* @handles must be last */
};

static size_t bus1_transaction_size(struct bus1_cmd_send *param)
{
	/* make sure @size cannot overflow */
	BUILD_BUG_ON(BUS1_VEC_MAX > U16_MAX);
	BUILD_BUG_ON(BUS1_FD_MAX > U16_MAX);

	/* make sure we do not violate alignment rules */
	BUILD_BUG_ON(__alignof(struct bus1_transaction) <
		     __alignof(struct iovec));
	BUILD_BUG_ON(__alignof(struct iovec) < __alignof(struct file *));

	return sizeof(struct bus1_transaction) +
	       param->n_vecs * sizeof(struct iovec) +
	       param->n_fds * sizeof(struct file *) +
	       bus1_handle_batch_inline_size(param->n_handles);
}

static void bus1_transaction_init(struct bus1_transaction *transaction,
				  struct bus1_peer *peer,
				  struct bus1_cmd_send *param)
{
	transaction->peer = peer;
	transaction->peer_info = bus1_peer_dereference(peer);
	transaction->param = param;
	transaction->cred = current_cred();
	transaction->pid = task_tgid(current);
	transaction->tid = task_pid(current);

	transaction->vecs = (void *)(transaction + 1);
	transaction->files = (void *)(transaction->vecs + param->n_vecs);
	memset(transaction->files, 0, param->n_vecs * sizeof(struct file *));

	transaction->length_vecs = 0;
	transaction->entries = NULL;
	bus1_handle_transfer_init(&transaction->handles, param->n_handles);
}

static void bus1_transaction_destroy(struct bus1_transaction *transaction)
{
	struct bus1_peer_info *peer_info;
	struct bus1_message *message;
	struct bus1_handle *handle;
	struct bus1_peer *peer;
	size_t i;

	while ((message = transaction->entries)) {
		transaction->entries = message->transaction.next;
		handle = message->transaction.handle;
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		message->transaction.next = NULL;
		message->transaction.handle = NULL;
		message->transaction.raw_peer = NULL;

		mutex_lock(&peer_info->lock);
		WARN_ON(bus1_queue_node_is_queued(&message->qnode));
		bus1_message_deallocate_locked(message, peer_info);
		mutex_unlock(&peer_info->lock);

		bus1_message_free(message);
		bus1_handle_release_pinned(handle, peer_info);
		bus1_handle_unref(handle);
		bus1_peer_release(peer);
	}

	for (i = 0; i < transaction->param->n_fds; ++i)
		if (transaction->files[i])
			fput(transaction->files[i]);

	bus1_handle_transfer_destroy(&transaction->handles);
}

static int bus1_transaction_import_vecs(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const struct iovec __user *ptr_vecs;

	ptr_vecs = (const struct iovec __user *)(unsigned long)param->ptr_vecs;
	return bus1_import_vecs(transaction->vecs, &transaction->length_vecs,
				ptr_vecs, param->n_vecs,
				bus1_in_compat_syscall());
}

static int bus1_transaction_import_handles(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const u64 __user *ptr_handles;

	ptr_handles = (const u64 __user *)(unsigned long)param->ptr_handles;
	return bus1_handle_transfer_instantiate(&transaction->handles,
						transaction->peer_info,
						ptr_handles,
						param->n_handles);
}

static int bus1_transaction_import_files(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const int __user *ptr_fds;
	struct file *f;
	size_t i;

	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	for (i = 0; i < param->n_fds; ++i) {
		f = bus1_import_fd(ptr_fds + i);
		if (IS_ERR(f))
			return PTR_ERR(f);

		transaction->files[i] = f;
	}

	return 0;
}

/**
 * bus1_transaction_new_from_user() - create new transaction
 * @stack_buffer:		stack buffer to use as backing memory
 * @stack_size:			size of @stack_buffer in bytes
 * @peer:			origin of this transaction
 * @param:			transaction parameters
 *
 * This allocates a new transaction object for a user-transaction as specified
 * via @param. The transaction is optionally put onto the stack, if the passed
 * buffer @stack_buffer is big enough. Otherwise, the memory is allocated. The
 * caller must make sure to pass the same stack-pointer to
 * bus1_transaction_free().
 *
 * The transaction object imports all its data from user-space. If anything
 * fails, an error is returned.
 *
 * Note that the transaction object relies on being local to the current task.
 * That is, its lifetime must be limited to your own function lifetime. You
 * must not pass pointers to transaction objects to contexts outside of this
 * lifetime.
 * This allows to optimize access to 'current' (and its properties like creds
 * and pids), and to place the transaction on the stack, if possible.
 *
 * Return: Pointer to transaction object, or ERR_PTR on failure.
 */
struct bus1_transaction *
bus1_transaction_new_from_user(u8 *stack_buffer,
			       size_t stack_size,
			       struct bus1_peer *peer,
			       struct bus1_cmd_send *param)
{
	struct bus1_transaction *transaction;
	size_t size;
	int r;

	/* use caller-provided stack buffer, if possible */
	size = bus1_transaction_size(param);
	if (unlikely(size > stack_size)) {
		transaction = kmalloc(size, GFP_TEMPORARY);
		if (!transaction)
			return ERR_PTR(-ENOMEM);
	} else {
		transaction = (void *)stack_buffer;
	}
	bus1_transaction_init(transaction, peer, param);

	r = bus1_transaction_import_vecs(transaction);
	if (r < 0)
		goto error;

	r = bus1_transaction_import_handles(transaction);
	if (r < 0)
		goto error;

	r = bus1_transaction_import_files(transaction);
	if (r < 0)
		goto error;

	return transaction;

error:
	bus1_transaction_free(transaction, stack_buffer);
	return ERR_PTR(r);
}

/**
 * bus1_transaction_free() - free transaction
 * @transaction:	transaction to free, or NULL
 * @stack_buffer:	stack buffer passed to constructor
 *
 * This releases a transaction and all associated memory. If the transaction
 * failed, any in-flight messages are dropped and pinned peers are released. If
 * the transaction was successfull, this just releases the temporary data that
 * was used for the transmission.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_transaction *
bus1_transaction_free(struct bus1_transaction *transaction, u8 *stack_buffer)
{
	if (!transaction)
		return NULL;

	bus1_transaction_destroy(transaction);

	if (transaction != (void *)stack_buffer)
		kfree(transaction);

	return NULL;
}

static struct bus1_message *
bus1_transaction_instantiate(struct bus1_transaction *transaction,
			     struct bus1_peer_info *peer_info,
			     struct bus1_handle *handle,
			     struct bus1_user *user)
{
	struct bus1_message *message;
	size_t i, slice_size;
	bool silent;
	int r;

	silent = transaction->param->flags & BUS1_SEND_FLAG_SILENT;

	message = bus1_message_new(transaction->length_vecs,
				   transaction->param->n_fds,
				   transaction->param->n_handles,
				   silent);
	if (IS_ERR(message))
		return ERR_CAST(message);

	/* cannot overflow as all of those are limited */
	slice_size = ALIGN(transaction->length_vecs, 8) +
		     ALIGN(transaction->param->n_handles * sizeof(u64), 8) +
		     ALIGN(transaction->param->n_fds * sizeof(int), 8);

	message->data.destination = bus1_handle_get_owner_id(handle);
	message->data.uid = from_kuid_munged(peer_info->cred->user_ns,
					     transaction->cred->uid);
	message->data.gid = from_kgid_munged(peer_info->cred->user_ns,
					     transaction->cred->gid);
	message->data.pid = pid_nr_ns(transaction->pid, peer_info->pid_ns);
	message->data.tid = pid_nr_ns(transaction->tid, peer_info->pid_ns);

	for (i = 0; i < transaction->param->n_fds; ++i)
		message->files[i] = get_file(transaction->files[i]);

	r = bus1_handle_inflight_instantiate(&message->handles, peer_info,
					     &transaction->handles);
	if (r < 0)
		goto error;

	mutex_lock(&peer_info->lock);
	r = bus1_message_allocate_locked(message, peer_info, user, slice_size);
	mutex_unlock(&peer_info->lock);
	if (r < 0)
		goto error;

	r = bus1_pool_write_iovec(&peer_info->pool,	/* pool to write */
				  message->slice,	/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->param->n_vecs, /* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0)
		goto error;

	return message;

error:
	mutex_lock(&peer_info->lock);
	bus1_message_deallocate_locked(message, peer_info);
	mutex_unlock(&peer_info->lock);

	bus1_message_free(message);
	return ERR_PTR(r);
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @destination:	destination
 *
 * Instantiate the message from the given transaction for the peer given as
 * @peer_id. A new pool-slice is allocated, a queue entry is created and the
 * message is queued as in-flight message on the transaction object. The
 * message is not linked on the destination, yet. You need to commit the
 * transaction to actually link it on the destination queue.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_instantiate_for_id(struct bus1_transaction *transaction,
					struct bus1_user *user,
					u64 destination)
{
	struct bus1_peer_info *peer_info;
	struct bus1_message *message;
	struct bus1_handle *handle;
	struct bus1_peer *peer;
	bool cont;
	int r;

	cont = transaction->param->flags & BUS1_SEND_FLAG_CONTINUE;

	handle = bus1_handle_find_by_id(transaction->peer_info, destination);
	if (handle) {
		peer = bus1_handle_pin(handle);
		if (!peer)
			handle = bus1_handle_unref(handle);
	}
	if (!handle)
		return cont ? 0 : -ENXIO;

	peer_info = bus1_peer_dereference(peer);

	message = bus1_transaction_instantiate(transaction, peer_info,
					       handle, user);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		message = NULL;
		goto error;
	}

	message->transaction.next = transaction->entries;
	message->transaction.handle = handle;
	message->transaction.raw_peer = peer;
	transaction->entries = message;
	bus1_active_lockdep_released(&peer->active);

	return 0;

error:
	if (r < 0 && cont) {
		if (atomic_inc_return(&peer_info->n_dropped) == 1)
			bus1_peer_wake(peer);
		r = 0;
	}
	bus1_handle_release_pinned(handle, peer_info);
	bus1_handle_unref(handle);
	bus1_peer_release(peer);
	return r;
}

/**
 * bus1_transaction_commit() - commit a transaction
 * @transaction:	transaction to commit
 *
 * This performs the final commit of this transaction. All instances of the
 * message that have been created on this transaction are staged on their
 * respective destination queues and committed. This function makes sure to
 * adhere to global-order restrictions, hence, the caller *must* instantiate
 * the message for each destination before committing the whole transaction.
 * Otherwise, ordering might not be guaranteed.
 *
 * This function flushes the entire transaction. Technically, you can
 * instantiate further entries once this call returns and commit them again.
 * However, they will be treated as a new message which just happens to have
 * the same contents as the previous one. This might come in handy for messages
 * that might be triggered multiple times (like peer notifications).
 *
 * This function never fails. If you successfully instantiated all your
 * entries, they will always be correctly committed without failure.
 */
void bus1_transaction_commit(struct bus1_transaction *transaction)
{
	struct bus1_peer_info *peer_info;
	struct bus1_message *message, *list;
	struct bus1_handle *handle;
	struct bus1_peer *peer;
	bool wake, silent;
	u64 timestamp;

	/* nothing to do for empty destination sets */
	if (!transaction->entries)
		return;

	list = transaction->entries;
	transaction->entries = NULL;
	timestamp = bus1_queue_tick(&transaction->peer_info->queue);
	silent = transaction->param->flags & BUS1_SEND_FLAG_SILENT;

	/*
	 * Before queueing a message as staging entry in the destination queue,
	 * we sync the remote clock with our timestamp, and possible update our
	 * own timestamp in case we're behind. This guarantees that no peer
	 * will see events "from the future", and also that we keep the range
	 * we block as small as possible.
	 *
	 * As last step, we perform a clock tick on the remote clock, to make
	 * sure it actually treated the message as a real unique event. And
	 * eventually queue the message as staging entry.
	 */
	for (message = list; message; message = message->transaction.next) {
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		/* sync clocks and queue message as staging entry */
		mutex_lock(&peer_info->lock);
		timestamp = bus1_queue_sync(&peer_info->queue, timestamp);
		timestamp = bus1_queue_tick(&peer_info->queue);
		wake = bus1_queue_stage(&peer_info->queue, &message->qnode,
					timestamp - 1);
		mutex_unlock(&peer_info->lock);

		if (wake)
			bus1_peer_wake(peer);

		bus1_active_lockdep_released(&peer->active);
	}

	/* XXX: @timestamp vs handle->node->timestamp */

	/*
	 * We now queued our message on all destinations, and we're guaranteed
	 * that any racing message is now blocked by our staging entries.
	 * However, to support side-channel synchronization, we must first sync
	 * all clocks to the final commit-timestamp, before actually performing
	 * the final commit. If we didn't do that, then between the first
	 * commit and the last commit, we're have a short timespan that might
	 * cause side-channel messages with lower timestamps than our own
	 * commit. Hence, sync the clocks to at least the commit-timestamp,
	 * *before* doing the first commit. Any side-channel message generated,
	 * can only cause messages with a higher commit afterwards.
	 *
	 * This step can be skipped if side-channels should not be synced. But
	 * we actually want to give that guarantee, so here we go..
	 */
	for (message = list; message; message = message->transaction.next) {
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->lock);
		bus1_queue_sync(&peer_info->queue, timestamp);
		mutex_unlock(&peer_info->lock);

		bus1_active_lockdep_released(&peer->active);
	}

	/*
	 * Our message is queued with the *same* timestamp on all destinations.
	 * Now do the final commit and release each message.
	 *
	 * _Iff_ the target queue was reset in between, then our message might
	 * have been unlinked. In that case, we still own the message, but
	 * should silently drop the instance. We must not treat it as failure,
	 * but rather as an explicit drop of the receiver.
	 */
	while ((message = list)) {
		list = message->transaction.next;
		handle = message->transaction.handle;
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		message->transaction.next = NULL;
		message->transaction.handle = NULL;
		message->transaction.raw_peer = NULL;

		bus1_handle_inflight_install(&message->handles, peer,
					     &transaction->handles,
					     transaction->peer);
		bus1_handle_inflight_commit(&message->handles, timestamp);

		mutex_lock(&peer_info->lock);
		if (bus1_queue_node_is_queued(&message->qnode)) {
			/* this transfers ownerhip of @message to the queue */
			wake = bus1_queue_stage(&peer_info->queue,
						&message->qnode, timestamp);
			message = NULL;
		} else {
			wake = false;
			bus1_message_deallocate_locked(message, peer_info);
		}
		mutex_unlock(&peer_info->lock);

		if (wake)
			bus1_peer_wake(peer);

		bus1_message_free(message);
		bus1_handle_release_pinned(handle, peer_info);
		bus1_handle_unref(handle);
		bus1_peer_release(peer);
	}
}

/**
 * bus1_transaction_commit_for_id() - instantiate and commit unicast
 * @transaction:	transaction to use
 * @destination:	destination ID
 *
 * This is a fast-path for unicast messages. It is equivalent to calling
 * bus1_transaction_instantiate_for_id(), followed by a commit.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_commit_for_id(struct bus1_transaction *transaction,
				   struct bus1_user *user,
				   u64 destination)
{
	struct bus1_peer_info *peer_info;
	struct bus1_message *message;
	struct bus1_handle *handle;
	struct bus1_peer *peer;
	bool wake, cont;
	u64 timestamp;
	int r;

	cont = transaction->param->flags & BUS1_SEND_FLAG_CONTINUE;

	handle = bus1_handle_find_by_id(transaction->peer_info, destination);
	if (handle) {
		peer = bus1_handle_pin(handle);
		if (!peer)
			handle = bus1_handle_unref(handle);
	}
	if (!handle)
		return cont ? 0 : -ENXIO;

	peer_info = bus1_peer_dereference(peer);
	timestamp = bus1_queue_tick(&transaction->peer_info->queue);

	message = bus1_transaction_instantiate(transaction, peer_info,
					       handle, user);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		message = NULL;
		goto exit;
	}

	bus1_handle_inflight_install(&message->handles, peer,
				     &transaction->handles,
				     transaction->peer);

	mutex_lock(&peer_info->lock);
	timestamp = bus1_queue_sync(&peer_info->queue, timestamp);
	timestamp = bus1_queue_tick(&peer_info->queue);
	/* XXX: @timestamp vs. @handle->node->timestamp */
	bus1_handle_inflight_commit(&message->handles, timestamp);
	/* transfers message ownership to the queue */
	wake = bus1_queue_stage(&peer_info->queue, &message->qnode, timestamp);
	mutex_unlock(&peer_info->lock);

	if (wake)
		bus1_peer_wake(peer);

	r = 0;

exit:
	if (r < 0 && cont) {
		if (atomic_inc_return(&peer_info->n_dropped) == 1)
			bus1_peer_wake(peer);
		r = 0;
	}
	bus1_handle_release_pinned(handle, peer_info);
	bus1_handle_unref(handle);
	bus1_peer_release(peer);
	return r;
}
