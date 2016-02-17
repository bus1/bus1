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
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "domain.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "user.h"
#include "util.h"

/*
 * This constant defines the iovecs that are needed in addition to the
 * user-supplied iovecs. Right now, only a single additional iovec is needed,
 * which is used to point to the kernel-copy of the message header.
 */
#define BUS1_TRANSACTION_EXTRA_VECS (1)

struct bus1_transaction_header {
	u64 sender;
	u64 destination;
	u32 uid;
	u32 gid;
} __aligned(8);

struct bus1_transaction {
	/* sender context */
	struct bus1_peer_info *peer_info;
	struct bus1_domain *domain;

	/* transaction state */
	size_t length_vecs;
	struct bus1_transaction_header header;
	u64 timestamp;

	/* payload */
	size_t n_vecs;
	size_t n_files;
	struct iovec *vecs;
	struct file **files;

	/* destinations */
	struct rb_root entries;
};

static struct bus1_transaction *
bus1_transaction_new(size_t n_vecs, size_t n_files, void *buf, size_t buf_len)
{
	struct bus1_transaction *transaction;
	size_t size;

	/* make sure @size cannot overflow */
	BUILD_BUG_ON(BUS1_VEC_MAX > U16_MAX);
	BUILD_BUG_ON(BUS1_FD_MAX > U16_MAX);

	/* make sure we do not violate alignment rules */
	BUILD_BUG_ON(__alignof(struct bus1_transaction) <
		     __alignof(struct iovec));
	BUILD_BUG_ON(__alignof(struct iovec) < __alignof(struct file *));

	/* allocate space for our own iovecs */
	n_vecs += BUS1_TRANSACTION_EXTRA_VECS;

	/* allocate all memory in a single chunk */
	size = sizeof(*transaction);
	size += n_vecs * sizeof(*transaction->vecs);
	size += n_files * sizeof(*transaction->files);

	if (size <= buf_len) {
		transaction = buf;
	} else {
		transaction = kmalloc(size, GFP_TEMPORARY);
		if (!transaction)
			return ERR_PTR(-ENOMEM);
	}

	memset(transaction, 0, size);

	/* only reserve space, don't claim it */
	transaction->vecs = (void *)(transaction + 1);
	transaction->files = (void *)(transaction->vecs + n_vecs);

	/* skip extra-vecs initially, just guarantee they're there */
	transaction->vecs += BUS1_TRANSACTION_EXTRA_VECS;

	transaction->entries = RB_ROOT;

	return transaction;
}

static int
bus1_transaction_import_vecs(struct bus1_transaction *transaction,
			     struct bus1_cmd_send *param,
			     bool is_compat)
{
	const struct iovec __user *ptr_vecs;
	int r;

	if (WARN_ON(transaction->n_vecs > 0))
		return -EINVAL;

	ptr_vecs = (const struct iovec __user *)(unsigned long)param->ptr_vecs;
	r = bus1_import_vecs(transaction->vecs, &transaction->length_vecs,
			     ptr_vecs, param->n_vecs, is_compat);
	if (r < 0)
		return r;

	transaction->n_vecs = param->n_vecs;
	return 0;
}

static int
bus1_transaction_import_files(struct bus1_transaction *transaction,
			      struct bus1_cmd_send *param)
{
	const int __user *ptr_fds;
	struct file *f;
	size_t i;

	if (WARN_ON(transaction->n_files > 0))
		return -EINVAL;

	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	for (i = 0; i < transaction->n_files; ++i) {
		f = bus1_import_fd(ptr_fds + i);
		if (IS_ERR(f))
			return PTR_ERR(f);

		transaction->files[transaction->n_files++] = f;
	}

	return 0;
}

static int
bus1_transaction_import_message(struct bus1_transaction *transaction)
{
	struct iov_iter iter;
	size_t l;

	iov_iter_init(&iter, READ, transaction->vecs, transaction->n_vecs,
		      transaction->length_vecs);

	/*
	 * The specs says short, fixed-size types should default to their
	 * pre-defined values. Luckily, those pre-defined values equal all 0,
	 * so we are good if the user specified a short message.
	 * We just need to make sure we didn't fault in this copy operation. In
	 * this case, the user tried to supply more but failed.
	 */
	l = copy_from_iter(&transaction->header,
			   sizeof(transaction->header),
			   &iter);
	if (l < sizeof(transaction->header) && l != transaction->length_vecs)
		return -EFAULT;

	/* make sure user-space clears values that we fill in */
	if (transaction->header.sender != 0 ||
	    transaction->header.destination != 0 ||
	    transaction->header.uid != 0 ||
	    transaction->header.gid != 0)
		return -EPERM;

	/*
	 * We copied the header into kernel space, to fill in trusted data.
	 * Hence, those vecs must be skipped on the final copy.
	 * copy_from_iter() already adjusted the iterator, so all we have to do
	 * is merge that information back into our own information.
	 */
	transaction->length_vecs -= l;
	transaction->n_vecs -= iter.iov - transaction->vecs;
	transaction->vecs = (struct iovec *)iter.iov;
	if (iter.iov_offset > 0) {
		if (WARN_ON(transaction->n_vecs == 0 ||
			    iter.iov_offset > transaction->vecs->iov_len))
			return -EFAULT;

		transaction->vecs->iov_base += iter.iov_offset;
		transaction->vecs->iov_len -= iter.iov_offset;
	}

	/*
	 * Now that all vecs are adjusted to contain only the remaining data,
	 * we have to prepend our own vector that points to the header.
	 */
	BUILD_BUG_ON(BUS1_TRANSACTION_EXTRA_VECS < 1);
	--transaction->vecs;
	++transaction->n_vecs;
	transaction->vecs->iov_base = &transaction->header;
	transaction->vecs->iov_len = sizeof(transaction->header);
	transaction->length_vecs += sizeof(transaction->header);

	/* XXX: fill in header */

	return 0;
}

/**
 * bus1_transaction_new_from_user() - XXX
 */
struct bus1_transaction *
bus1_transaction_new_from_user(struct bus1_peer_info *peer_info,
			       struct bus1_domain *domain,
			       struct bus1_cmd_send *param,
			       void *buf,
			       size_t buf_len,
			       bool is_compat)
{
	struct bus1_transaction *transaction;
	int r;

	transaction = bus1_transaction_new(param->n_vecs, param->n_fds,
					   buf, buf_len);
	if (IS_ERR(transaction))
		return ERR_CAST(transaction);

	transaction->peer_info = peer_info;
	transaction->domain = domain;

	r = bus1_transaction_import_vecs(transaction, param, is_compat);
	if (r < 0)
		goto error;

	r = bus1_transaction_import_files(transaction, param);
	if (r < 0)
		goto error;

	/* make sure vecs+files does not overflow */
	if (transaction->length_vecs + transaction->n_files * sizeof(int) <
	    transaction->length_vecs) {
		r = -EMSGSIZE;
		goto error;
	}

	r = bus1_transaction_import_message(transaction);
	if (r < 0)
		goto error;

	return transaction;

error:
	bus1_transaction_free(transaction, transaction != buf);
	return ERR_PTR(r);
}

/**
 * bus1_transaction_free() - free transaction
 * @transaction:	transaction to free, or NULL
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
bus1_transaction_free(struct bus1_transaction *transaction, bool do_free)
{
	struct bus1_message *message, *t;
	struct bus1_peer_info *peer_info;
	struct bus1_peer *peer;
	size_t i;

	if (!transaction)
		return NULL;

	/* release all in-flight queue entries and their pinned peers */
	rbtree_postorder_for_each_entry_safe(message, t,
					     &transaction->entries, dd.rb) {
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		message->transaction.raw_peer = NULL;

		mutex_lock(&peer_info->lock);
		WARN_ON(bus1_queue_node_is_queued(&message->qnode));
		bus1_message_deallocate_locked(message, peer_info);
		mutex_unlock(&peer_info->lock);

		bus1_message_free(message);
		bus1_peer_release(peer);
	}

	/* release message payload */
	for (i = 0; i < transaction->n_files; ++i)
		if (transaction->files[i])
			fput(transaction->files[i]);

	if (do_free)
		kfree(transaction);

	return NULL;
}

static int bus1_transaction_instantiate(struct bus1_transaction *transaction,
					struct bus1_message *message,
					struct bus1_peer_info *peer_info,
					struct bus1_user *user)
{
	size_t i, slice_size;
	int r;

	slice_size = ALIGN(transaction->length_vecs, 8) +
		     ALIGN(transaction->n_files * sizeof(int), 8);

	/* files must be set *before* allocating the slice */
	for (i = 0; i < transaction->n_files; ++i)
		message->files[i] = get_file(transaction->files[i]);
	message->n_files = transaction->n_files;

	/* allocate the slice */
	mutex_lock(&peer_info->lock);
	r = bus1_message_allocate_locked(message, peer_info, user, slice_size);
	mutex_unlock(&peer_info->lock);
	if (r < 0)
		return r;

	/*
	 * Copy data into @slice. Only the real message (@length_vecs) is
	 * copied, the trailing FD array is left uninitialized. They're filled
	 * in when the message is received.
	 */
	r = bus1_pool_write_iovec(&peer_info->pool,	/* pool to write */
				  message->slice,	/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->n_vecs,	/* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0) {
		mutex_lock(&peer_info->lock);
		bus1_message_deallocate_locked(message, peer_info);
		mutex_unlock(&peer_info->lock);
		return r;
	}

	return 0;
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @destination:	destination
 * @flags:		BUS1_SEND_FLAG_* to affect behavior
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
					u64 destination,
					u64 flags)
{
	struct bus1_message *message = NULL, *iter;
	struct rb_node *n, **slot;
	struct bus1_peer *peer;
	int r;

	/* unknown peers are only ignored, if explicitly told so */
	peer = bus1_peer_acquire_by_id(transaction->domain, destination);
	if (!peer)
		return (flags & BUS1_SEND_FLAG_IGNORE_UNKNOWN) ? 0 : -ENXIO;

	message = bus1_message_new(transaction->n_files, 0);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		message = NULL;
		goto error;
	}

	/* duplicate detection */
	slot = &transaction->entries.rb_node;
	n = NULL;
	while (*slot) {
		n = *slot;
		iter = container_of(n, struct bus1_message, qnode.rb);
		if (destination < iter->dd.destination) {
			slot = &n->rb_left;
		} else if (destination > iter->dd.destination) {
			slot = &n->rb_right;
		} else /* if (destination == iter->dd.destination) */ {
			r = -ENOTUNIQ;
			goto error;
		}
	}

	r = bus1_transaction_instantiate(transaction, message,
					 bus1_peer_dereference(peer), user);
	if (r < 0)
		goto error;

	/* link into duplicate detection tree */
	rb_link_node(&message->dd.rb, n, slot);
	rb_insert_color(&message->dd.rb, &transaction->entries);
	message->dd.destination = destination;

	bus1_active_lockdep_released(&peer->active);
	message->transaction.raw_peer = peer;
	return 0;

error:
	bus1_message_free(message);
	if (r < 0 && (flags & BUS1_SEND_FLAG_CONVEY_ERRORS)) {
		/* XXX: convey error to @peer */
		r = 0;
	}
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
	struct bus1_message *message, *t, *list;
	struct bus1_peer *peer;
	u64 timestamp;
	bool wake;

	/* nothing to do for empty destination sets */
	if (RB_EMPTY_ROOT(&transaction->entries))
		return;

	list = NULL;
	timestamp = transaction->timestamp;

	/*
	 * We now have to queue all message on their respective destination
	 * queues. This requires us to drop them from the dd-tree and rather
	 * keep them in a single linked list (dd.rb nodes are shared with the
	 * qnode memory). Duplicate detection is already done, so we are fine
	 * with a single linked list.
	 *
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
	rbtree_postorder_for_each_entry_safe(message, t,
					     &transaction->entries, dd.rb) {
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		/* rb-tree is gone now, so remember all entries in a list */
		message->transaction.next = list;
		list = message;

		/* prepare qnode for queue insertion */
		bus1_queue_node_init(&message->qnode, true);

		/* sync clocks and queue message as staging entry */
		mutex_lock(&peer_info->lock);
		timestamp = bus1_queue_sync(&peer_info->queue, timestamp);
		timestamp = bus1_queue_tick(&peer_info->queue);
		wake = bus1_queue_stage(&peer_info->queue, &message->qnode,
					timestamp - 1);
		mutex_unlock(&peer_info->lock);

		WARN_ON(wake); /* XXX: initial queueing cannot wake anything */
		bus1_active_lockdep_released(&peer->active);
	}

	transaction->entries = RB_ROOT;
	transaction->timestamp = timestamp;

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
		peer = message->transaction.raw_peer;
		bus1_active_lockdep_acquired(&peer->active);
		peer_info = bus1_peer_dereference(peer);

		message->transaction.next = NULL;
		message->transaction.raw_peer = NULL;

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

		/* XXX: handle @wake */

		bus1_message_free(message);
		bus1_peer_release(peer);
	}
}

/**
 * bus1_transaction_commit_for_id() - instantiate and commit unicast
 * @transaction:	transaction to use
 * @peer_id:		destination ID
 * @flags:		BUS1_CMD_SEND_* flags
 *
 * This is a fast-path for unicast messages. It is equivalent to calling
 * bus1_transaction_instantiate_for_id(), followed by a commit.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_commit_for_id(struct bus1_transaction *transaction,
				   struct bus1_user *user,
				   u64 peer_id,
				   u64 flags)
{
	struct bus1_peer_info *peer_info;
	struct bus1_message *message;
	struct bus1_peer *peer;
	u64 timestamp;
	bool wake;
	int r;

	/* unknown peers are only ignored, if explicitly told so */
	peer = bus1_peer_acquire_by_id(transaction->domain, peer_id);
	if (!peer)
		return (flags & BUS1_SEND_FLAG_IGNORE_UNKNOWN) ? 0 : -ENXIO;

	peer_info = bus1_peer_dereference(peer);
	timestamp = transaction->timestamp;

	message = bus1_message_new(transaction->n_files, 0);
	if (IS_ERR(message)) {
		r = PTR_ERR(message);
		message = NULL;
		goto error;
	}

	r = bus1_transaction_instantiate(transaction, message, peer_info, user);
	if (r < 0)
		goto error;

	mutex_lock(&peer_info->lock);
	timestamp = bus1_queue_sync(&peer_info->queue, timestamp);
	timestamp = bus1_queue_tick(&peer_info->queue);
	/* transfers message ownership to the queue */
	wake = bus1_queue_stage(&peer_info->queue, &message->qnode, timestamp);
	mutex_unlock(&peer_info->lock);

	/* XXX: handle @wake */

	bus1_peer_release(peer);
	return 0;

error:
	bus1_message_free(message);
	if (r < 0 && (flags & BUS1_SEND_FLAG_CONVEY_ERRORS)) {
		/* XXX: convey error to @peer */
		r = 0;
	}
	bus1_peer_release(peer);
	return r;
}
