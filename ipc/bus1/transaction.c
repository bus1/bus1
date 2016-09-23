/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
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
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "security.h"
#include "transaction.h"
#include "user.h"
#include "util.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

struct bus1_transaction {
	/* sender context */
	struct bus1_peer *peer;
	struct bus1_cmd_send *param;
	const struct cred *cred;
	struct pid *pid;
	struct pid *tid;
	char *secctx;
	u32 n_secctx;

	/* flags */
	bool has_secctx : 1;
	bool has_faulted : 1;

	/* payload */
	struct iovec *vecs;
	struct file **files;

	/* transaction state */
	int error;
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
	transaction->param = param;
	transaction->cred = current_cred();
	transaction->pid = task_tgid(current);
	transaction->tid = task_pid(current);
	transaction->secctx = NULL;
	transaction->n_secctx = 0;

	transaction->has_secctx = false;
	transaction->has_faulted = false;

	transaction->vecs = (void *)((u8 *)(transaction + 1) +
			bus1_handle_batch_inline_size(param->n_handles));
	transaction->files = (void *)(transaction->vecs + param->n_vecs);
	memset(transaction->files, 0, param->n_fds * sizeof(struct file *));

	transaction->error = 0;
	transaction->length_vecs = 0;
	transaction->entries = NULL;
	bus1_handle_transfer_init(&transaction->handles, param->n_handles);
}

static void bus1_transaction_destroy(struct bus1_transaction *transaction)
{
	struct bus1_peer *peer;
	struct bus1_handle_dest dest;
	struct bus1_peer_list link;
	struct bus1_message *message;
	size_t i;

	while ((message = transaction->entries)) {
		link = message->transaction.link;
		dest = message->transaction.dest;
		transaction->entries = link.next;
		peer = bus1_peer_list_bind(&link);

		mutex_lock(&peer->data.lock);
		bus1_queue_remove(&peer->data.queue, &peer->waitq,
				  &message->qnode);
		mutex_unlock(&peer->data.lock);

		bus1_message_unpin(message, peer);
		bus1_message_unref(message);

		bus1_peer_list_unbind(&link);
		bus1_handle_dest_destroy(&dest, transaction->peer);
	}

	for (i = 0; i < transaction->param->n_fds; ++i)
		bus1_fput(transaction->files[i]);

	bus1_handle_transfer_release(&transaction->handles,
				     transaction->peer);
	bus1_handle_transfer_destroy(&transaction->handles);

	if (transaction->has_secctx)
		security_release_secctx(transaction->secctx,
					transaction->n_secctx);
}

static int bus1_transaction_import_secctx(struct bus1_transaction *transaction)
{
	u32 sid;
	int r;

	security_task_getsecid(current, &sid);
	r = security_secid_to_secctx(sid, &transaction->secctx,
				     &transaction->n_secctx);
	if (r == -EOPNOTSUPP)
		return 0; /* no LSM with secctx support loaded */
	if (r < 0)
		return r;

	transaction->has_secctx = true;
	return 0;
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
					   transaction->peer,
					   ptr_handles,
					   param->n_handles);
}

static int bus1_transaction_import_files(struct bus1_transaction *transaction)
{
	struct bus1_cmd_send *param = transaction->param;
	const int __user *ptr_fds;
	struct file *f;
	size_t i;
	int fd;

	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	for (i = 0; i < param->n_fds; ++i) {
		if (unlikely(get_user(fd, ptr_fds + i)))
			return -EFAULT;

		f = bus1_import_fd(fd);
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

	r = bus1_transaction_import_secctx(transaction);
	if (r < 0)
		goto error;

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
 * the transaction was successful, this just releases the temporary data that
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
				     struct bus1_peer *peer)
{
	struct bus1_message *message;
	const bool want_secctx = READ_ONCE(peer->flags) &
						BUS1_PEER_FLAG_WANT_SECCTX;
	const bool transmit_secctx = want_secctx && transaction->has_secctx;
	size_t offset, i;
	struct kvec vec;
	int r;

	r = security_bus1_transfer_message(transaction->peer, peer);
	if (r < 0)
		return ERR_PTR(r);

	message = bus1_message_new(transaction->length_vecs,
				   transaction->param->n_fds,
				   transaction->param->n_handles,
				   transmit_secctx ? transaction->n_secctx : 0,
				   transaction->peer);
	if (IS_ERR(message))
		return message;

	r = bus1_message_allocate(message, peer);
	if (r < 0) {
		bus1_message_unref(message);
		return ERR_PTR(r);
	}

	r = bus1_pool_write_iovec(&peer->data.pool,	/* pool to write to */
				  message->slice,	/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->param->n_vecs, /* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0)
		goto error;

	if (transmit_secctx) {
		offset = ALIGN(message->n_bytes, 8) +
			 ALIGN(message->handles.batch.n_entries * sizeof(u64),
			       8) +
			 ALIGN(message->n_files * sizeof(int), 8);
		vec = (struct kvec){
			.iov_base = transaction->secctx,
			.iov_len = transaction->n_secctx,
		};

		r = bus1_pool_write_kvec(&peer->data.pool,
					 message->slice,
					 offset,
					 &vec,
					 1,
					 vec.iov_len);
		if (r < 0)
			goto error;

		message->flags |= BUS1_MSG_FLAG_HAS_SECCTX;
	}

	r = bus1_handle_inflight_import(&message->handles, peer,
					&transaction->handles,
					transaction->peer);
	if (r < 0)
		goto error;

	message->uid = from_kuid_munged(peer->cred->user_ns,
					transaction->cred->uid);
	message->gid = from_kgid_munged(peer->cred->user_ns,
					transaction->cred->gid);
	message->pid = pid_nr_ns(transaction->pid, peer->pid_ns);
	message->tid = pid_nr_ns(transaction->tid, peer->pid_ns);

	for (i = 0; i < transaction->param->n_fds; ++i) {
		r = security_bus1_transfer_file(transaction->peer,
						peer,
						transaction->files[i]);
		if (r < 0)
			goto error;

		message->files[i] = get_file(transaction->files[i]);
	}

	return message;

error:
	bus1_message_unpin(message, peer);
	bus1_message_unref(message);
	return ERR_PTR(r);
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @index:		index into destination array
 *
 * Instantiate the message from the given transaction for the handle id
 * at @index in the destination array. A new pool-slice is allocated, a queue
 * entry is created and the message is queued as in-flight message on the
 * transaction object. The message is not linked on the destination, yet. You
 * need to commit the transaction to actually link it on the destination queue.
 */
void bus1_transaction_instantiate_for_id(struct bus1_transaction *transaction,
					 size_t index)
{
	struct bus1_cmd_send *param = transaction->param;
	struct bus1_peer *peer;
	u64 __user *idp, __user *errorp;
	struct bus1_handle_dest dest;
	struct bus1_peer_list link;
	struct bus1_message *message;
	int r;

	idp = (u64 __user *)(unsigned long)param->ptr_destinations;
	idp = idp + index;
	errorp = (u64 __user *)(unsigned long)param->ptr_errors;
	errorp = errorp ? errorp + index : NULL;

	bus1_handle_dest_init(&dest);

	r = bus1_handle_dest_import(&dest, transaction->peer, idp);
	if (r < 0)
		goto error;

	link.peer = dest.raw_peer;
	link.next = transaction->entries;

	peer = bus1_peer_list_bind(&link);
	message = bus1_transaction_instantiate_message(transaction, peer);
	bus1_peer_list_unbind(&link);

	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		goto error;
	}

	message->transaction.index = index;
	message->transaction.link = link; /* consume */
	message->transaction.dest = dest; /* consume */
	transaction->entries = message;

	return;

error:
	bus1_handle_dest_destroy(&dest, transaction->peer);
	/*
	 * If an error happens, we remember it for commit() to return. We always
	 * continue with the remaining messages of the transaction, so failure
	 * handling is predictable.
	 * If per-destination error-fields are provided, we additionally
	 * transfer the error code to user-space. If that fails, we remember to
	 * have faulted (which is always an out-of-band error code).
	 */
	transaction->error = r;
	if (errorp && put_user(r, errorp))
		transaction->has_faulted = true;
}

static void bus1_transaction_commit_one(struct bus1_transaction *transaction,
					struct bus1_message *message,
					struct bus1_handle_dest *dest,
					u64 timestamp)
{
	struct bus1_peer *peer = dest->raw_peer;
	u64 id;

	mutex_lock(&peer->lock);
	id = bus1_handle_dest_export(dest, peer, timestamp,
				     message->qnode.sender, true);
	mutex_unlock(&peer->lock);
	if (id == BUS1_HANDLE_INVALID) {
		/*
		 * The destination node is no longer valid, and the CONTINUE
		 * flag was set. Drop the message.
		 */
		mutex_lock(&peer->data.lock);
		bus1_queue_remove(&peer->data.queue, &peer->waitq,
				  &message->qnode);
		mutex_unlock(&peer->data.lock);

		bus1_message_unpin(message, peer);
	} else {
		bool committed;

		message->destination = id;

		mutex_lock(&peer->data.lock);
		committed = bus1_queue_commit_staged(&peer->data.queue,
						     &peer->waitq,
						     &message->qnode,
						     timestamp);
		mutex_unlock(&peer->data.lock);

		if (!committed) {
			/*
			 * The message has been flushed from the queue, but it
			 * has not been cleaned up. Release all resources.
			 */
			bus1_message_unpin(message, peer);
		}
	}

	bus1_message_unref(message);
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
	struct bus1_peer *peer;
	struct bus1_message *message, *list;
	u64 __user *idp, __user *errorp;
	struct bus1_handle_dest dest;
	struct bus1_peer_list link;
	u64 id, timestamp;
	int r;

	list = transaction->entries;
	timestamp = 0;
	idp = (u64 __user *)(unsigned long)param->ptr_destinations;
	errorp = (u64 __user *)(unsigned long)param->ptr_errors;

	/*
	 * Add each message to its destination queue as a staging entry. The
	 * message cannot be dequeued and blocks (until the message is finally
	 * committed) any future messages on each queue from being dequeued too.
	 * However, no messages that were finally committed before this message
	 * was staged are blocked. At the end of the loop, it is guaranteed that
	 * all messages after @timestamp are blocked on all destination queues.
	 */
	for (message = list; message; message = message->transaction.link.next) {
		peer = bus1_peer_list_bind(&message->transaction.link);
		mutex_lock(&peer->data.lock);
		timestamp = bus1_queue_stage(&peer->data.queue,
					     &peer->waitq,
					     &message->qnode,
					     timestamp);
		mutex_unlock(&peer->data.lock);
		bus1_peer_list_unbind(&message->transaction.link);
	}

	/*
	 * Acquire the actual timestamp to use from the sending queue. It must
	 * be no less than @timestamp, and it must be locally unique for the
	 * sending clock. Note that it may not be unique on the destination
	 * queues.
	 */
	mutex_lock(&transaction->peer->data.lock);
	timestamp = bus1_queue_sync(&transaction->peer->data.queue, timestamp);
	timestamp = bus1_queue_tick(&transaction->peer->data.queue);
	mutex_unlock(&transaction->peer->data.lock);

	/*
	 * Sync all the destination queues to the final timestamp. This
	 * guarantees that by the time the first message is ready to be
	 * dequeued, none of the other destination queues may use a lower
	 * timestamp than the final one for this transaction.
	 */
	for (message = list; message; message = message->transaction.link.next) {
		peer = bus1_peer_list_bind(&message->transaction.link);

		mutex_lock(&peer->data.lock);
		bus1_queue_sync(&peer->data.queue, timestamp);
		mutex_unlock(&peer->data.lock);

		mutex_lock(&peer->lock);
		id = bus1_handle_dest_export(&message->transaction.dest,
					     peer, timestamp,
					     message->qnode.sender, false);
		mutex_unlock(&peer->lock);

		bus1_peer_list_unbind(&message->transaction.link);

		r = 0;
		if (id == BUS1_HANDLE_INVALID)
			r = transaction->error = -EHOSTUNREACH;
		else if (message->transaction.dest.idp &&
			 put_user(id, idp + message->transaction.index))
			transaction->has_faulted = true;

		if (errorp && put_user(r, errorp + message->transaction.index))
			transaction->has_faulted = true;
	}

	if (transaction->has_faulted)
		return -EFAULT;
	if (transaction->error < 0 &&
	    !(transaction->param->flags & BUS1_SEND_FLAG_CONTINUE))
		return transaction->error;

	if (param->n_handles) {
		idp = (u64 __user *)(unsigned long)param->ptr_handles;
		mutex_lock(&transaction->peer->lock);
		r = bus1_handle_transfer_export(&transaction->handles,
						transaction->peer,
						idp, param->n_handles);
		mutex_unlock(&transaction->peer->lock);
		if (r < 0)
			return r;
	}

	/*
	 * Actually commit each message using the final timestamp. Each message
	 * is committed with the same timestamp, and their global ordering is
	 * therefore guaranteed to be consistent. Note that there may be several
	 * messages with the same final timestamp on any given queue, as the
	 * timestamp is only guaranteed to be unique locally for the sending
	 * clock. To still guarantee a total order, messages with the same
	 * timestamp are ordered by their sending peer. For this to work, it
	 * must be guaranteed that all messages with the same timestamp are
	 * finally committed before any of them can be dequeued (or their order
	 * would not be stable). This is guaranteed as each final timestamp is
	 * strictly greater than the corresponding staging timestamps, so all
	 * messages with the same final timestamps will be blockd by all the
	 * corresponding staging messages.
	 */
	while ((message = transaction->entries)) {
		link = message->transaction.link;
		dest = message->transaction.dest;
		transaction->entries = link.next;

		peer = bus1_peer_list_bind(&link);

		bus1_handle_inflight_install(&message->handles, dest.raw_peer);
		bus1_transaction_commit_one(transaction, message, &dest,
					    timestamp);

		bus1_peer_list_unbind(&link);
		bus1_handle_dest_destroy(&dest, transaction->peer);
	}

	return 0;
}

/**
 * bus1_transaction_commit_seed() - instantiate and commit seed
 * @transaction:	transaction to use
 *
 * This instantiates a new message with the given transaction, and commits it
 * as new seed on the owner-peer of the transaction. Any existing seed is
 * deallocated and freed.
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
						    transaction->peer);
	if (IS_ERR(seed))
		return PTR_ERR(seed);

	mutex_lock(&transaction->peer->lock);
	r = bus1_handle_transfer_export(&transaction->handles,
					transaction->peer,
					idp, transaction->param->n_handles);
	mutex_unlock(&transaction->peer->lock);
	if (r < 0)
		goto exit;

	bus1_handle_inflight_install(&seed->handles, transaction->peer);

	swap(seed, transaction->peer->local.seed);

exit:
	bus1_message_unpin(seed, transaction->peer);
	bus1_message_unref(seed);
	return r;
}
