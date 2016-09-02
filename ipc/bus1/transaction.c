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
#include <linux/cgroup.h>
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
#include "active.h"
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "security.h"
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
	struct cgroup *cgroup;
	char *secctx;
	u32 n_secctx;

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
	/* only the unified cgroup hierarchy is supported */
	transaction->cgroup = task_cgroup(current, 1);
	transaction->secctx = NULL;
	transaction->n_secctx = 0;

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

		bus1_queue_remove(&peer_info->queue, &message->qnode);
		bus1_message_unpin(message, peer_info);
		bus1_message_unref(message);
		bus1_active_lockdep_released(&dest.raw_peer->active);
		bus1_handle_dest_destroy(&dest, transaction->peer_info);
	}

	for (i = 0; i < transaction->param->n_fds; ++i)
		bus1_fput(transaction->files[i]);

	bus1_handle_transfer_release(&transaction->handles,
				     transaction->peer_info);
	bus1_handle_transfer_destroy(&transaction->handles);

	security_release_secctx(transaction->secctx, transaction->n_secctx);
}

static int bus1_transaction_set_secctx(struct bus1_transaction *transaction)
{
#ifdef CONFIG_SECURITY
	u32 sid;
	int r;

	BUS1_WARN_ON(transaction->secctx || transaction->n_secctx);

	security_task_getsecid(current, &sid);
	if (!sid)
		return 0;

	r = security_secid_to_secctx(sid, &transaction->secctx,
				     &transaction->n_secctx);
	if (r < 0)
		return r;
#endif

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
	int fd;

	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	for (i = 0; i < param->n_fds; ++i) {
		if (unlikely(get_user(fd, ptr_fds + i)))
			return -EFAULT;

		f = bus1_import_fd(fd, false);
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

	r = bus1_transaction_set_secctx(transaction);
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
	u8 padding[7] = {};
	struct kvec vecs[3] = {
		{
			.iov_base = transaction->secctx,
			.iov_len = transaction->n_secctx,
		},
		{
			.iov_base = &padding,
			.iov_len = transaction->n_secctx % 8,
		}
	};
	void *page = NULL;
#ifdef CONFIG_CGROUPS
	char *cgroup;
#endif
	size_t n_cgroup = 0, offset, length, i;
	int r;

	r = security_bus1_transfer_message(transaction->peer_info, peer_info);
	if (r < 0)
		return ERR_PTR(r);

#ifdef CONFIG_CGROUPS
	page = (void *) __get_free_page(GFP_TEMPORARY);
	if (!page)
		return ERR_PTR(-ENOMEM);

	cgroup = cgroup_path_ns(transaction->cgroup, page, PAGE_SIZE,
				peer_info->cgroup_ns);
	n_cgroup = cgroup ? strlen(cgroup) + 1 : 0;

	vecs[2].iov_base = cgroup;
	vecs[2].iov_len = n_cgroup;
#endif

	message = bus1_message_new(transaction->length_vecs,
				   transaction->param->n_fds,
				   transaction->param->n_handles,
				   transaction->n_secctx,
				   n_cgroup,
				   transaction->peer_info);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		message = NULL;
		goto error;
	}

	r = bus1_message_allocate(message, peer_info);
	if (r < 0) {
		/*
		 * If BUS1_SEND_FLAG_CONTINUE is specified, target errors are
		 * not fatal. That is, any error that is caused by the *target*,
		 * rather than the sender, will not cause an abort of the
		 * transaction.
		 */
		if ((transaction->param->flags & BUS1_SEND_FLAG_CONTINUE) &&
		    (r == -EXFULL || r == -EDQUOT))
			r = 0;
		goto error;
	}

	r = bus1_pool_write_iovec(&peer_info->pool,	/* pool to write to */
				  message->slice,	/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->param->n_vecs, /* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0)
		goto error;

	offset = ALIGN(message->n_bytes, 8) +
		 ALIGN(message->handles.batch.n_entries * sizeof(u64), 8) +
		 ALIGN(message->n_files * sizeof(int), 8);
	length = vecs[0].iov_len + vecs[1].iov_len + vecs[2].iov_len;

	r = bus1_pool_write_kvec(&peer_info->pool,	/* pool to write to */
				 message->slice,	/* slice to write to */
				 offset,		/* offset into slice */
				 vecs,			/* vectors */
				 3,			/* #n vectors */
				 length);		/* total length */
	if (r < 0)
		goto error;

	r = bus1_handle_inflight_import(&message->handles, peer_info,
					&transaction->handles,
					transaction->peer_info);
	if (r < 0)
		goto error;

	message->uid = from_kuid_munged(peer_info->cred->user_ns,
					transaction->cred->uid);
	message->gid = from_kgid_munged(peer_info->cred->user_ns,
					transaction->cred->gid);
	message->pid = pid_nr_ns(transaction->pid, peer_info->pid_ns);
	message->tid = pid_nr_ns(transaction->tid, peer_info->pid_ns);

	for (i = 0; i < transaction->param->n_fds; ++i) {
		r = security_bus1_transfer_file(transaction->peer_info,
						peer_info,
						transaction->files[i]);
		if (r < 0)
			goto error;

		message->files[i] = get_file(transaction->files[i]);
	}

	free_page((unsigned long)page);
	return message;

error:
	if (message)
		bus1_message_unpin(message, peer_info);
	if (r < 0) {
		bus1_message_unref(message);
		message = ERR_PTR(r);
	}
	free_page((unsigned long)page);
	return message;
}

static struct bus1_message *
bus1_transaction_instantiate(struct bus1_transaction *transaction,
			     struct bus1_handle_dest *dest,
			     u64 __user *idp,
			     u64 __user *errorp)
{
	struct bus1_peer_info *peer_info = NULL;
	struct bus1_message *message;
	int r;

	r = bus1_handle_dest_import(dest, transaction->peer, idp, errorp);
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
 * @errorp:		user-space pointer with destination errno
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
					u64 __user *idp, u64 __user *errorp)
{
	struct bus1_handle_dest dest;
	struct bus1_message *message;
	int r;

	bus1_handle_dest_init(&dest);

	message = bus1_transaction_instantiate(transaction, &dest, idp, errorp);
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

static void bus1_transaction_commit_one(struct bus1_transaction *transaction,
					struct bus1_message *message,
					struct bus1_handle_dest *dest,
					u64 timestamp)
{
	struct bus1_peer_info *peer_info;
	u64 id;

	peer_info = bus1_peer_dereference(dest->raw_peer);

	if (!message->slice) {
		/*
		 * The message failed to be allocated, due to an error at the
		 * receiver, and the CONTINUE flag was set. Drop the message
		 * without informing the sender. The count of dropped messages
		 * is increased in the receiving queue.
		 */
		bus1_queue_remove(&peer_info->queue, &message->qnode);
		bus1_message_unref(message);
		return;
	}

	mutex_lock(&peer_info->lock);
	id = bus1_handle_dest_export(dest, peer_info, timestamp,
				     message->qnode.sender, true);
	mutex_unlock(&peer_info->lock);
	if (id == BUS1_HANDLE_INVALID) {
		/*
		 * The destination node is no longer valid, and the CONTINUE
		 * flag was set. Drop the message.
		 */
		bus1_queue_remove(&peer_info->queue, &message->qnode);
		bus1_message_unpin(message, peer_info);
		bus1_message_unref(message);
		return;
	}

	message->destination = id;

	if (!bus1_queue_commit_staged(&peer_info->queue, &message->qnode,
				      timestamp)) {
		/*
		 * The message has been flushed from the queue, but it has not
		 * been cleaned up. Release all resources.
		 */
		bus1_message_unpin(message, peer_info);
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
	struct bus1_peer_info *peer_info;
	struct bus1_message *message, *list;
	struct bus1_handle_dest dest;
	struct bus1_peer *peer;
	u64 id, timestamp;
	u64 __user *idp, *errorp;
	int r = 0;

	list = transaction->entries;
	timestamp = 0;

	/*
	 * Add each message to its destination queue as a staging entry. The
	 * message cannot be dequeued and blocks (until the message is finally
	 * committed) any future messages on each queue from being dequeued too.
	 * However, no messages that were finally committed before this message
	 * was staged are blocked. At the end of the loop, it is guananteed that
	 * all messages after @timestamp are blocked on all destination queues.
	 */
	for (message = list; message; message = message->transaction.next) {
		peer = message->transaction.dest.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->queue.lock);
		timestamp = bus1_queue_stage(&peer_info->queue, &message->qnode,
					     timestamp);
		mutex_unlock(&peer_info->queue.lock);

		bus1_active_lockdep_released(&peer->active);
	}

	/*
	 * Acquire the actual timestamp to use from the sending queue. It must
	 * be no less than @timestamp, and it must be locally unique for the
	 * sending clock. Note that it may not be unique on the destination
	 * queues.
	 */
	mutex_lock(&transaction->peer_info->queue.lock);
	timestamp = bus1_queue_sync(&transaction->peer_info->queue, timestamp);
	timestamp = bus1_queue_tick(&transaction->peer_info->queue);
	mutex_unlock(&transaction->peer_info->queue.lock);

	/*
	 * Sync all the destination queues to the final timestamp. This
	 * guarantees that by the time the first message is ready to be
	 * dequeued, none of the other destination queues may use a lower
	 * timestamp than the final one for this transaction.
	 */
	for (message = list; message; message = message->transaction.next) {
		int error = message->error;

		peer = message->transaction.dest.raw_peer;
		idp = message->transaction.dest.idp;
		errorp = message->transaction.dest.errorp;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->queue.lock);
		bus1_queue_sync(&peer_info->queue, timestamp);
		mutex_unlock(&peer_info->queue.lock);

		mutex_lock(&peer_info->lock);
		id = bus1_handle_dest_export(&message->transaction.dest,
					peer_info, timestamp,
					message->qnode.sender, false);
		mutex_unlock(&peer_info->lock);

		bus1_active_lockdep_released(&peer->active);

		if (id != BUS1_HANDLE_INVALID) {
			if (idp && put_user(id, idp))
				return -EFAULT;
		} else {
			error = EHOSTUNREACH;
		}

		if (errorp && put_user(error, errorp))
			return -EFAULT;

		if (error && r != -EHOSTUNREACH)
			r = -error;
	}

	if (r < 0 && !(transaction->param->flags & BUS1_SEND_FLAG_CONTINUE))
		return r;

	if (param->n_handles) {
		idp = (u64 __user *)(unsigned long)param->ptr_handles;
		mutex_lock(&transaction->peer_info->lock);
		r = bus1_handle_transfer_export(&transaction->handles,
						transaction->peer,
						idp, param->n_handles);
		mutex_unlock(&transaction->peer_info->lock);
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
		transaction->entries = message->transaction.next;
		dest = message->transaction.dest;

		message->transaction.next = NULL;
		message->transaction.dest = (struct bus1_handle_dest){};

		bus1_active_lockdep_acquired(&dest.raw_peer->active);
		peer_info = bus1_peer_dereference(dest.raw_peer);

		bus1_handle_inflight_install(&message->handles, dest.raw_peer);

		bus1_transaction_commit_one(transaction, message, &dest,
					    timestamp);

		bus1_active_lockdep_released(&dest.raw_peer->active);
		bus1_handle_dest_destroy(&dest, transaction->peer_info);
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
	struct bus1_queue_node *node;
	struct bus1_message *seed;
	u64 __user *idp;
	int r;

	idp = (u64 __user *)(unsigned long)transaction->param->ptr_handles;

	seed = bus1_transaction_instantiate_message(transaction,
						    transaction->peer_info);
	if (IS_ERR(seed))
		return PTR_ERR(seed);

	mutex_lock(&transaction->peer_info->lock);
	r = bus1_handle_transfer_export(&transaction->handles,
					transaction->peer,
					idp, transaction->param->n_handles);
	mutex_unlock(&transaction->peer_info->lock);
	if (r < 0)
		goto exit;

	bus1_handle_inflight_install(&seed->handles, transaction->peer);

	/* swap seed; we rely on possible old seeds to be messages as well */
	node = bus1_queue_xchg_seed(&transaction->peer_info->queue,
				    &seed->qnode);
	seed = node ? bus1_message_from_node(node) : NULL;

exit:
	if (seed) {
		bus1_message_unpin(seed, transaction->peer_info);
		bus1_message_unref(seed);
	}
	return r;
}
