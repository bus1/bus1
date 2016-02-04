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
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
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
	struct bus1_domain *domain;
	struct bus1_domain_info *domain_info;

	/* transaction state */
	size_t length_vecs;
	struct bus1_transaction_header header;

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
	struct bus1_queue_entry *entry;
	struct bus1_peer *peer;
	struct bus1_peer_info *peer_info;
	struct rb_node *node, *t;
	size_t i;

	if (!transaction)
		return NULL;

	/* release all in-flight queue entries and their pinned peers */
	for (node = rb_first_postorder(&transaction->entries);
	     node && ((t = rb_next_postorder(node)), true);
	     node = t) {
		entry = container_of(node, struct bus1_queue_entry, transaction.rb);
		peer = entry->transaction.peer;
		entry->transaction.peer = NULL;
	        RB_CLEAR_NODE(&entry->transaction.rb);

		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->lock);
		entry->slice = bus1_pool_release_kernel(&peer_info->pool,
							entry->slice);
		mutex_unlock(&peer_info->lock);

		bus1_peer_release_raw(peer);
		bus1_queue_entry_free(entry); /* fput()s entry->files[] */
	}

	transaction->entries = RB_ROOT;

	/* release message payload */
	for (i = 0; i < transaction->n_files; ++i)
		if (transaction->files[i])
			fput(transaction->files[i]);

	if (do_free)
		kfree(transaction);

	return NULL;
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
bus1_transaction_import_message(struct bus1_transaction *transaction,
				u64 sender_id)
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

	/* fill in header */
	transaction->header.sender = sender_id;

	return 0;
}

/**
 * bus1_transaction_new_from_user() - XXX
 */
struct bus1_transaction *
bus1_transaction_new_from_user(struct bus1_domain *domain,
			       struct bus1_domain_info *domain_info,
			       u64 sender_id,
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

	transaction->domain = domain;
	transaction->domain_info = domain_info;

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

	r = bus1_transaction_import_message(transaction, sender_id);
	if (r < 0)
		goto error;

	return transaction;

error:
	bus1_transaction_free(transaction, transaction != buf);
	return ERR_PTR(r);
}

static struct bus1_queue_entry *
bus1_transaction_instantiate(struct bus1_transaction *transaction,
			     struct bus1_peer_info *peer_info,
			     u64 peer_id)
{
	struct bus1_queue_entry *entry;
	struct bus1_pool_slice *slice;
	size_t i;
	int r;

	entry = bus1_queue_entry_new(transaction->n_files);
	if (IS_ERR(entry))
		return ERR_CAST(entry);

	/*
	 * Allocate unlinked pool slice. We need enough space to store the
	 * message *and* the trailing FD array. Overflows are already checked
	 * by the importer.
	 */
	mutex_lock(&peer_info->lock);
	slice = bus1_pool_alloc(&peer_info->pool,
				transaction->length_vecs +
				transaction->n_files * sizeof(int));
	mutex_unlock(&peer_info->lock);

	if (IS_ERR(slice)) {
		r = PTR_ERR(slice);
		slice = NULL;
		goto error;
	}

	/*
	 * Copy data into @slice. Only the real message (@length_vecs) is
	 * copied, the trailing FD array is left uninitialized. They're filled
	 * in when the message is received.
	 */
	r = bus1_pool_write_iovec(&peer_info->pool,	/* pool to write */
				  slice,		/* slice to write to */
				  0,			/* offset into slice */
				  transaction->vecs,	/* vectors */
				  transaction->n_vecs,	/* #n vectors */
				  transaction->length_vecs); /* total length */
	if (r < 0)
		goto error;

	/* link files into @entry */
	for (i = 0; i < transaction->n_files; ++i)
		entry->files[i] = get_file(transaction->files[i]);

	/* message was fully instantiated, store data and return */
	entry->slice = slice;
	entry->destination_id = peer_id;

	return entry;

error:
	if (slice) {
		mutex_lock(&peer_info->lock);
		bus1_pool_release_kernel(&peer_info->pool, slice);
		mutex_unlock(&peer_info->lock);
	}
	bus1_queue_entry_free(entry); /* fput()s entry->files[] */
	return ERR_PTR(r);
}

static int bus1_transaction_link(struct bus1_transaction *transaction,
				  struct bus1_queue_entry *entry)
{
	struct bus1_queue_entry *iter;
	struct rb_node *prev, **slot;

	WARN_ON(!RB_EMPTY_NODE(&entry->transaction.rb));

	slot = &transaction->entries.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = container_of(prev, struct bus1_queue_entry, transaction.rb);
		if (entry->destination_id < iter->destination_id) {
			slot = &prev->rb_left;
		} else if (entry->destination_id > iter->destination_id) {
			slot = &prev->rb_right;
		} else /* if (entry->destination_id == iter->destination_id) */ {
			return -ENOTUNIQ;
		}
	}

	rb_link_node(&entry->transaction.rb, prev, slot);
	rb_insert_color(&entry->transaction.rb, &transaction->entries);

	return 0;
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @peer_id:		destination
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
					u64 peer_id,
					u64 flags)
{
	struct bus1_queue_entry *entry;
	struct bus1_peer *peer;
	int r;

	/* unknown peers are only ignored, if explicitly told so */
	peer = bus1_peer_acquire_raw_by_id(transaction->domain, peer_id);
	if (!peer)
		return (flags & BUS1_SEND_FLAG_IGNORE_UNKNOWN) ? 0 : -ENXIO;

	entry = bus1_transaction_instantiate(transaction,
					     bus1_peer_dereference(peer),
					     peer_id);
	if (IS_ERR(entry)) {
		r = PTR_ERR(entry);
		entry = NULL;
		goto error;
	}

	/* link message into transaction */
	entry->transaction.peer = peer;
	r = bus1_transaction_link(transaction, entry);
	if (r < 0)
		goto error;

	return 0;

error:
	if (flags & BUS1_SEND_FLAG_CONVEY_ERRORS) {
		/* XXX: convey error to @peer */
		r = 0;
	}

	if (entry && entry->slice) {
		struct bus1_peer_info *peer_info;

		peer_info = bus1_peer_dereference(peer);

		mutex_lock(&peer_info->lock);
		bus1_pool_release_kernel(&peer_info->pool, entry->slice);
		mutex_unlock(&peer_info->lock);

		entry->slice = NULL;
		entry->transaction.peer = NULL;

		bus1_queue_entry_free(entry);
	}

	bus1_peer_release_raw(peer);
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
	struct rb_node *node, *first, *second, *t;
	struct bus1_queue_entry *e;
	struct bus1_peer *peer;
	struct bus1_peer_info *peer_info;
	bool wake;
	u64 seq = 0;

	/* nothing to do for empty destination sets */
	if (RB_EMPTY_ROOT(&transaction->entries))
		return;

	/* second destination; in the unicast case, we should be using
	 * bus1_transaction_commit_for_id() instead */
	first = rb_first_postorder(&transaction->entries);
	second = rb_next_postorder(first);
	WARN_ON(!second);

	/*
	 * Stamp all entries with a staging sequence number, and link them into
	 * their queues. They're marked as in-flight and cannot be unlinked by
	 * anyone but us. We just have to make sure we keep the peer pinned.
	 *
	 * Note that the first entry can be skipped. It is the first entry that
	 * is committed in the following loop, hence, there is no reason to
	 * mark it as staging. The only requirement we have is once we commit
	 * the first entry, all others have to be staged. This allows us to
	 * skip the first entry, and immediately start staging with the second
	 * entry.
	 *
	 * We pick a temporary sequence number greater than all messages
	 * (including unicast ones) delivered before the next
	 * multicast message and smaller than the next multicast
	 * message */
	seq = atomic64_read(&transaction->domain_info->seq_ids) + 3;
	WARN_ON(!(seq & 1)); /* must be odd */

	for (node = second; node; node = rb_next_postorder(node)) {
		e = container_of(node, struct bus1_queue_entry, transaction.rb);
		peer_info = bus1_peer_dereference(e->transaction.peer);

		mutex_lock(&peer_info->lock);
		wake = bus1_queue_link(&peer_info->queue, e, seq);
		mutex_unlock(&peer_info->lock);

		WARN_ON(wake); /* in-flight; cannot cause a wake-up */
	}

	/*
	 * Now that all entries (but the first) are linked as in-flight, we
	 * allocate the final sequence number for our transaction. Then  we
	 * stamp all entries again and commit them into their respective queues.
	 * Once we drop the peer-lock, each entry is owned by the peer and we
	 * must not dereference it, anymore. It might get dequeued at any time.
	 */
	for (node = first;
	     node && ((t = rb_next_postorder(node)), true);
	     node = t) {
		e = container_of(node, struct bus1_queue_entry, transaction.rb);
		peer = e->transaction.peer;
		peer_info = bus1_peer_dereference(peer);

		RB_CLEAR_NODE(&e->transaction.rb);
		e->transaction.peer = NULL;

		mutex_lock(&peer_info->lock);
		if (node == first) {
			seq = atomic64_add_return(4,
					&transaction->domain_info->seq_ids);
			WARN_ON(seq & 1); /* must be even */
			wake = bus1_queue_link(&peer_info->queue, e, seq);
		} else {
			WARN_ON(seq == 0); /* must be assigned */
			wake = bus1_queue_relink(&peer_info->queue, e, seq);
		}
		mutex_unlock(&peer_info->lock);

		if (wake)
			/* XXX: wake up peer */ ;

		bus1_peer_release_raw(peer);
	}

	transaction->entries = RB_ROOT;
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
				   u64 peer_id,
				   u64 flags)
{
	struct bus1_peer *peer;
	struct bus1_queue_entry *e;
	struct bus1_peer_info *peer_info;
	bool wake;
	u64 seq;
	int r;

	/* unknown peers are only ignored, if explicitly told so */
	peer = bus1_peer_acquire_raw_by_id(transaction->domain, peer_id);
	if (!peer)
		return (flags & BUS1_SEND_FLAG_IGNORE_UNKNOWN) ? 0 : -ENXIO;

	peer_info = bus1_peer_dereference(peer);

	e = bus1_transaction_instantiate(transaction, peer_info, peer_id);
	if (IS_ERR(e)) {
		r = PTR_ERR(e);
		e = NULL;
		goto exit;
	}

	/*
	 * Unicast messages get a shared sequence number, strictly between the
	 * previous and the next multicast message.
	 */
	mutex_lock(&peer_info->lock);
	seq = atomic64_read(&transaction->domain_info->seq_ids) + 2;
	WARN_ON(seq & 1); /* must be even */
	wake = bus1_queue_link(&peer_info->queue, e, seq);
	mutex_unlock(&peer_info->lock);

	if (wake)
		/* XXX: wake up peer */ ;

	r = 0;

exit:
	if (r < 0 && (flags & BUS1_SEND_FLAG_CONVEY_ERRORS)) {
		/* XXX: convey error to @peer */
		r = 0;
	}
	bus1_peer_release_raw(peer);
	return r;
}
