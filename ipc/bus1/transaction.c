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
#include "active.h"
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
		     __alignof(union bus1_handle_entry));
	BUILD_BUG_ON(__alignof(union bus1_handle_entry) <
		     __alignof(struct iovec));
	BUILD_BUG_ON(__alignof(struct iovec) < __alignof(struct file *));

	return sizeof(struct bus1_transaction) +
	       bus1_handle_batch_inline_size(param->n_handles) +
	       param->n_vecs * sizeof(struct iovec) +
	       param->n_fds * sizeof(struct file *);
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

	transaction->vecs = (void *)((u8 *)(transaction + 1) +
			bus1_handle_batch_inline_size(param->n_handles));
	transaction->files = (void *)(transaction->vecs + param->n_vecs);
	memset(transaction->files, 0, param->n_fds * sizeof(struct file *));

	transaction->length_vecs = 0;
	transaction->entries = NULL;
	bus1_handle_transfer_init(&transaction->handles, param->n_handles);
}

static void bus1_transaction_destroy(struct bus1_transaction *transaction)
{
	struct bus1_peer_info *peer_info;
	struct bus1_handle_dest dest;
	struct bus1_message *message;
	size_t i;

	while ((message = transaction->entries)) {
		transaction->entries = message->transaction.next;
		dest = message->transaction.dest;
		bus1_active_lockdep_acquired(&dest.raw_peer->active);
		peer_info = bus1_peer_dereference(dest.raw_peer);

		message->transaction.next = NULL;
		message->transaction.dest = (struct bus1_handle_dest){};

		mutex_lock(&peer_info->qlock);
		if (bus1_queue_remove(&peer_info->queue, &message->qnode))
			wake_up_interruptible(peer_info->waitq);
		mutex_unlock(&peer_info->qlock);

		mutex_lock(&peer_info->lock);
		bus1_message_deallocate(message, peer_info);
		mutex_unlock(&peer_info->lock);

		bus1_active_lockdep_released(&dest.raw_peer->active);
		bus1_message_free(message, peer_info);
		bus1_handle_dest_destroy(&dest, transaction->peer_info);
	}

	for (i = 0; i < transaction->param->n_fds; ++i)
		if (transaction->files[i])
			fput(transaction->files[i]);

	bus1_handle_transfer_destroy(&transaction->handles,
				     transaction->peer_info);
}

static int bus1_transaction_import_vecs(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const struct iovec __user *ptr_vecs;

	ptr_vecs = (const struct iovec __user *)(unsigned long)param->ptr_vecs;
	return bus1_import_vecs(transaction->vecs, &transaction->length_vecs,
				ptr_vecs, param->n_vecs);
}

static int bus1_transaction_import_handles(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const u64 __user *ptr_handles;

	ptr_handles = (const u64 __user *)(unsigned long)param->ptr_handles;
	return bus1_handle_transfer_import(&transaction->handles,
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
 * lifetime. This makes it possible to optimize access to 'current' (and its
 * properties like creds and pids), and to place the transaction on the stack,
 * when it fits.
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
bus1_transaction_instantiate_message(struct bus1_transaction *transaction,
				     struct bus1_peer_info *peer_info)
{
	struct bus1_message *message;
	size_t i;
	int r;

	message = bus1_message_new(transaction->length_vecs,
			transaction->param->n_fds,
			transaction->param->n_handles,
			(unsigned long)transaction->peer_info);
	if (IS_ERR(message))
		return message;

	mutex_lock(&peer_info->lock);
	r = bus1_message_allocate(message, peer_info,
				  transaction->peer_info->user);
	mutex_unlock(&peer_info->lock);
	if (r < 0) {
		/*
		 * If BUS1_SEND_FLAG_CONTINUE is specified, target errors are
		 * ignored. That is, any error that is caused by the *target*,
		 * rather than the sender, will not cause an abort of the
		 * transaction. Instead, we keep the erroneous message and will
		 * signal the target during commit.
		 */
		if (transaction->param->flags & BUS1_SEND_FLAG_CONTINUE)
			r = 0;
		goto error;
	}

	r = bus1_pool_write_iovec(&peer_info->pool,	/* pool to write */
				  message->slice,	/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->param->n_vecs, /* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0)
		goto error;

	r = bus1_handle_inflight_import(&message->handles, peer_info,
					&transaction->handles);
	if (r < 0)
		goto error;

	message->data.uid = from_kuid_munged(peer_info->cred->user_ns,
					     transaction->cred->uid);
	message->data.gid = from_kgid_munged(peer_info->cred->user_ns,
					     transaction->cred->gid);
	message->data.pid = pid_nr_ns(transaction->pid, peer_info->pid_ns);
	message->data.tid = pid_nr_ns(transaction->tid, peer_info->pid_ns);

	for (i = 0; i < transaction->param->n_fds; ++i)
		message->files[i] = get_file(transaction->files[i]);

	return message;

error:
	if (message) {
		mutex_lock(&peer_info->lock);
		bus1_message_deallocate(message, peer_info);
		mutex_unlock(&peer_info->lock);
	}
	if (r < 0) {
		bus1_message_free(message, peer_info);
		message = ERR_PTR(r);
	}
	return message;
}

static struct bus1_message *
bus1_transaction_instantiate(struct bus1_transaction *transaction,
			     struct bus1_handle_dest *dest,
			     u64 __user *idp)
{
	struct bus1_peer_info *peer_info = NULL;
	struct bus1_message *message;
	int r;

	r = bus1_handle_dest_import(dest, transaction->peer, idp);
	if (r < 0)
		return ERR_PTR(r);

	bus1_active_lockdep_acquired(&dest->raw_peer->active);
	peer_info = bus1_peer_dereference(dest->raw_peer);
	message = bus1_transaction_instantiate_message(transaction, peer_info);
	bus1_active_lockdep_released(&dest->raw_peer->active);

	return message;
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @idp:		user-space pointer with destination ID
 *
 * Instantiate the message from the given transaction for the handle id
 * in @idp. A new pool-slice is allocated, a queue entry is created and the
 * message is queued as in-flight message on the transaction object. The
 * message is not linked on the destination, yet. You need to commit the
 * transaction to actually link it on the destination queue.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_instantiate_for_id(struct bus1_transaction *transaction,
					u64 __user *idp)
{
	struct bus1_handle_dest dest;
	struct bus1_message *message;
	int r;

	bus1_handle_dest_init(&dest);

	message = bus1_transaction_instantiate(transaction, &dest, idp);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		goto error;
	}

	message->transaction.next = transaction->entries;
	message->transaction.dest = dest; /* consume */
	transaction->entries = message;

	return 0;

error:
	bus1_handle_dest_destroy(&dest, transaction->peer_info);
	return r;
}

static bool
bus1_transaction_commit_one(struct bus1_transaction *transaction,
			    struct bus1_message *message,
			    struct bus1_handle_dest *dest,
			    u64 timestamp)
{
	struct bus1_peer_info *peer_info;
	u64 id;

	peer_info = bus1_peer_dereference(dest->raw_peer);
	lockdep_assert_held(&peer_info->lock);

	id = BUS1_HANDLE_INVALID;

	if (!message->slice) {
		if (bus1_queue_drop(&peer_info->queue))
			wake_up_interruptible(peer_info->waitq);
	} else if (bus1_queue_node_is_queued(&message->qnode)) {
		id = bus1_handle_dest_export(dest, peer_info, timestamp, true);
	}

	if (id == BUS1_HANDLE_INVALID) {
		bus1_queue_remove(&peer_info->queue, &message->qnode);
		return false;
	}

	message->data.destination = id;
	if (bus1_queue_stage(&peer_info->queue, &message->qnode, timestamp))
		wake_up_interruptible(peer_info->waitq);

	return true;
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
 * Otherwise, ordering would not be guaranteed.
 *
 * This function flushes the entire transaction. Technically, you can
 * instantiate further entries once this call returns and commit them again.
 * However, they will be treated as a new message which just happens to have
 * the same contents as the previous one. This might come in handy for messages
 * that might be triggered multiple times (like peer notifications).
 *
 * This function may fail if the handle id of newly allocated nodes cannot be
 * written back to the caller. Errors due to racing node destructions are
 * silently ignored.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_commit(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	struct bus1_peer_info *peer_info;
	struct bus1_message *message, *list;
	struct bus1_handle_dest dest;
	struct bus1_peer *peer;
	u64 id, timestamp;
	u64 __user *idp;
	bool res;
	int r;

	if (!transaction->entries)
		return 0;

	list = transaction->entries;
	timestamp = 0;

	for (message = list; message; message = message->transaction.next) {
		peer = message->transaction.dest.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->qlock);
		timestamp = bus1_queue_sync(&peer_info->queue, timestamp);
		timestamp = bus1_queue_tick(&peer_info->queue);
		if (bus1_queue_stage(&peer_info->queue, &message->qnode,
				     timestamp - 1))
			wake_up_interruptible(peer_info->waitq);
		mutex_unlock(&peer_info->qlock);

		bus1_active_lockdep_released(&peer->active);
	}

	mutex_lock(&transaction->peer_info->qlock);
	timestamp = bus1_queue_sync(&transaction->peer_info->queue, timestamp);
	timestamp = bus1_queue_tick(&transaction->peer_info->queue);
	mutex_unlock(&transaction->peer_info->qlock);

	mutex_lock(&transaction->peer_info->lock);
	bus1_handle_transfer_install(&transaction->handles, transaction->peer);
	mutex_unlock(&transaction->peer_info->lock);

	for (message = list; message; message = message->transaction.next) {
		peer = message->transaction.dest.raw_peer;
		idp = message->transaction.dest.idp;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->lock);
		mutex_lock(&peer_info->qlock);

		bus1_queue_sync(&peer_info->queue, timestamp);

		id = bus1_handle_dest_export(&message->transaction.dest,
					     peer_info, timestamp,
					     false);
		r = (idp && put_user(id, idp)) ? -EFAULT : 0;

		mutex_unlock(&peer_info->qlock);
		mutex_unlock(&peer_info->lock);

		bus1_active_lockdep_released(&peer->active);

		if (r < 0)
			return r;
	}

	idp = (u64 __user *)(unsigned long)param->ptr_handles;
	mutex_lock(&transaction->peer_info->lock);
	r = bus1_handle_transfer_export(&transaction->handles,
					transaction->peer_info,
					idp, param->n_handles);
	mutex_unlock(&transaction->peer_info->lock);
	if (r < 0)
		return r;

	while ((message = transaction->entries)) {
		transaction->entries = message->transaction.next;
		dest = message->transaction.dest;

		message->transaction.next = NULL;
		message->transaction.dest = (struct bus1_handle_dest){};

		bus1_active_lockdep_acquired(&dest.raw_peer->active);
		peer_info = bus1_peer_dereference(dest.raw_peer);

		bus1_handle_inflight_install(&message->handles, dest.raw_peer);

		mutex_lock(&peer_info->lock);
		mutex_lock(&peer_info->qlock);
		res = bus1_transaction_commit_one(transaction, message, &dest,
						  timestamp);
		mutex_unlock(&peer_info->qlock);
		if (!res)
			bus1_message_deallocate(message, peer_info);
		mutex_unlock(&peer_info->lock);

		if (!res)
			bus1_message_free(message, peer_info);
		bus1_active_lockdep_released(&dest.raw_peer->active);
		bus1_handle_dest_destroy(&dest, transaction->peer_info);
	}

	return 0;
}

/**
 * bus1_transaction_commit_for_id() - instantiate and commit unicast
 * @transaction:	transaction to use
 * @idp:		user-space pointer with destination ID
 *
 * This is a fast-path for unicast messages. It is equivalent to calling
 * bus1_transaction_instantiate_for_id(), followed by bus1_transaction_commit().
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_commit_for_id(struct bus1_transaction *transaction,
				   u64 __user *idp)
{
	int r;

	r = bus1_transaction_instantiate_for_id(transaction, idp);
	if (r < 0)
		return r;

	return bus1_transaction_commit(transaction);
}

/**
 * bus1_transaction_commit_seed() - instantiate and commit seed
 * @transaction:	transaction to use
 *
 * This instantiates a new message with the given transaction, and commits it
 * as new seed on the owner-peer of the transaction.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_commit_seed(struct bus1_transaction *transaction)
{
	struct bus1_message *seed;
	u64 __user *idp;
	int r;

	idp = (u64 __user *)(unsigned long)transaction->param->ptr_handles;

	seed = bus1_transaction_instantiate_message(transaction,
						    transaction->peer_info);
	if (IS_ERR(seed))
		return PTR_ERR(seed);

	mutex_lock(&transaction->peer_info->lock);
	bus1_handle_transfer_install(&transaction->handles, transaction->peer);
	r = bus1_handle_transfer_export(&transaction->handles,
					transaction->peer_info,
					idp, transaction->param->n_handles);
	if (r < 0) {
		bus1_message_deallocate(seed, transaction->peer_info);
		mutex_unlock(&transaction->peer_info->lock);
		goto exit;
	}
	mutex_unlock(&transaction->peer_info->lock);

	bus1_handle_inflight_install(&seed->handles, transaction->peer);

	mutex_lock(&transaction->peer_info->lock);
	swap(seed, transaction->peer_info->seed);
	if (seed)
		bus1_message_deallocate(seed, transaction->peer_info);
	mutex_unlock(&transaction->peer_info->lock);

exit:
	bus1_message_free(seed, transaction->peer_info);
	return r;
}
