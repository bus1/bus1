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
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "domain.h"
#include "filesystem.h"
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
	struct bus1_fs_domain *fs_domain;
	struct bus1_domain *domain;

	/* transaction state */
	size_t length_vecs;
	struct bus1_transaction_header header;
	u64 seq;

	/* payload */
	size_t n_vecs;
	size_t n_files;
	struct iovec *vecs;
	struct file **files;

	/* destinations */
	struct bus1_queue_entry *entries;
};

static struct bus1_transaction *
bus1_transaction_new(size_t n_vecs, size_t n_files)
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

	transaction = kzalloc(size, GFP_TEMPORARY);
	if (!transaction)
		return ERR_PTR(-ENOMEM);

	/* only reserve space, don't claim it */
	transaction->n_vecs = 0;
	transaction->n_files = 0;
	transaction->vecs = (void *)(transaction + 1);
	transaction->files = (void *)(transaction->vecs + n_vecs);

	/* skip extra-vecs initially, just guarantee they're there */
	transaction->vecs += BUS1_TRANSACTION_EXTRA_VECS;

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
bus1_transaction_free(struct bus1_transaction *transaction)
{
	struct bus1_queue_entry *entry;
	struct bus1_fs_peer *fs_peer;
	struct bus1_peer *peer;
	size_t i;

	if (!transaction)
		return NULL;

	/* release all in-flight queue entries and their pinned peers */
	while ((entry = transaction->entries)) {
		transaction->entries = entry->transaction.next;
		fs_peer = entry->transaction.fs_peer;
		entry->transaction.fs_peer = NULL;
		entry->transaction.next = NULL;

		peer = bus1_fs_peer_dereference(fs_peer);

		mutex_lock(&peer->lock);
		entry->slice = bus1_pool_release_kernel(&peer->pool,
							entry->slice);
		bus1_queue_unlink(&peer->queue, entry);
		mutex_unlock(&peer->lock);

		bus1_fs_peer_release(fs_peer);
		bus1_queue_entry_free(entry); /* fput()s entry->files[] */
	}

	/* release message payload */
	for (i = 0; i < transaction->n_files; ++i)
		if (transaction->files[i])
			fput(transaction->files[i]);

	kfree(transaction);

	return NULL;
}

static int
bus1_transaction_import_vecs(struct bus1_transaction *transaction,
			     struct bus1_cmd_send *param,
			     bool is_compat)
{
	int r;

	if (WARN_ON(transaction->n_vecs > 0))
		return -EINVAL;

	r = bus1_import_vecs(transaction->vecs,
			     &transaction->length_vecs,
			     (void __user *)param->ptr_vecs,
			     param->n_vecs,
			     is_compat);
	if (r < 0)
		return r;

	transaction->n_vecs = param->n_vecs;
	return 0;
}

static int
bus1_transaction_import_files(struct bus1_transaction *transaction,
			      struct bus1_cmd_send *param)
{
	struct file *f;
	size_t i;

	if (WARN_ON(transaction->n_files > 0))
		return -EINVAL;

	for (i = 0; i < transaction->n_files; ++i) {
		f = bus1_import_fd((int __user *)param->ptr_fds + i);
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
	 * The header is cleared in the constructor, so if it is short, we know
	 * its missing tail is zeroed. According to the spec, the default
	 * values must be assumed, which luckily is equivalent to treating it
	 * as zeroed data, in case of fixed-size objects. Therefore, short
	 * copies are fine, if they succeeded.
	 */
	l = copy_from_iter(&transaction->header,
			   sizeof(transaction->header),
			   &iter);
	if (l < transaction->length_vecs && l < sizeof(transaction->header))
		return -EFAULT;

	/* make sure user-space clears values that we fill in */
	if (transaction->header.sender != 0 ||
	    transaction->header.destination != 0 ||
	    transaction->header.uid != 0 ||
	    transaction->header.gid != 0)
		return -EPERM;

	/* sender is the same at all times, rest depends on destination */
	transaction->header.sender = sender_id;

	/*
	 * We copied the header into kernel space, to fill in trusted data.
	 * Hence, those vecs must be skipped on the final copy.
	 * copy_from_iter() already adjusted the iterator, so all we have to do
	 * is merge that information back into our own information.
	 */
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

	return 0;
}

/**
 * bus1_transaction_new_from_user() - XXX
 */
struct bus1_transaction *
bus1_transaction_new_from_user(struct bus1_fs_domain *fs_domain,
			       struct bus1_domain *domain,
			       u64 sender_id,
			       struct bus1_cmd_send *param,
			       bool is_compat)
{
	struct bus1_transaction *transaction;
	int r;

	transaction = bus1_transaction_new(param->n_vecs, param->n_fds);
	if (IS_ERR(transaction))
		return ERR_CAST(transaction);

	transaction->fs_domain = fs_domain;
	transaction->domain = domain;
	transaction->seq = atomic64_read(&domain->seq_ids);
	WARN_ON(!(transaction->seq & 1));

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
	bus1_transaction_free(transaction);
	return ERR_PTR(r);
}

/**
 * bus1_transaction_instantiate_for_id() - instantiate a message
 * @transaction:	transaction to work with
 * @peer_id:		destination
 * @flags:		BUS1_SEND_FLAG_* to affect behavior
 *
 * Instantiate the message from the given transaction for the peer given as
 * @peer_id. A new pool-slice is allocated, a queue entry is created and the
 * message is queued as in-flight message on the destination queue. The message
 * cannot be dequeued by the destination, until the entire transaction is
 * committed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_transaction_instantiate_for_id(struct bus1_transaction *transaction,
					u64 peer_id,
					u64 flags)
{
	struct bus1_queue_entry *entry = NULL;
	struct bus1_pool_slice *slice = NULL;
	struct bus1_fs_peer *fs_peer;
	struct bus1_peer *peer;
	bool wake;
	size_t i;
	int r;

	/* cannot instantiate on a uninitialized or committed transaction */
	if (WARN_ON(!(transaction->seq & 1)))
		return -EINVAL;

	/* unknown peers are only ignored, if explicitly told so */
	fs_peer = bus1_fs_peer_acquire_by_id(transaction->fs_domain, peer_id);
	if (!fs_peer)
		return (flags & BUS1_SEND_FLAG_IGNORE_UNKNOWN) ? 0 : -ENXIO;

	peer = bus1_fs_peer_dereference(fs_peer);

	/* allocate new, unlinked queue entry */
	entry = bus1_queue_entry_new(transaction->seq, transaction->n_files);
	if (IS_ERR(entry)) {
		r = PTR_ERR(entry);
		entry = NULL;
		goto error;
	}

	/*
	 * Allocate pool slice and link queue entry as in-flight message. We
	 * need enough space to store the message *and* the trailing FD array.
	 * Overflows are already checked by the importer.
	 */
	mutex_lock(&peer->lock);
	slice = bus1_pool_alloc(&peer->pool,
				transaction->length_vecs +
				transaction->n_files * sizeof(int),
				true);
	if (!IS_ERR(slice)) {
		wake = bus1_queue_link(&peer->queue, entry);
		WARN_ON(wake); /* in-flight messages cannot cause a wake-up */
	}
	mutex_unlock(&peer->lock);

	/* recover if we couldn't allocate a pool slice */
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
	r = bus1_pool_write_iovec(&peer->pool,		/* pool to write */
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
	entry->transaction.next = transaction->entries;
	entry->transaction.fs_peer = fs_peer;
	transaction->entries = entry;

	return 0;

error:
	if (slice) {
		mutex_lock(&peer->lock);
		bus1_queue_unlink(&peer->queue, entry);
		bus1_pool_release_kernel(&peer->pool, slice);
		mutex_unlock(&peer->lock);
	}
	bus1_queue_entry_free(entry); /* fput()s entry->files[] */
	if (flags & BUS1_SEND_FLAG_CONVEY_ERRORS) {
		/* XXX: convey error to @fs_peer */
		r = 0;
	}
	bus1_fs_peer_release(fs_peer);
	return r;
}

/**
 * bus1_transaction_commit() - commit a transaction
 * @transaction:	transaction to commit
 *
 * XXX:
 */
void bus1_transaction_commit(struct bus1_transaction *transaction)
{
	struct bus1_queue_entry *entry;
	struct bus1_fs_peer *fs_peer;
	struct bus1_peer *peer;

	/* cannot commit an uninitialized or committed transaction */
	if (WARN_ON(transaction->seq == 0 || !(transaction->seq & 1)))
		return;

	/* allocate final transaction ID, which must be even */
	transaction->seq =
			atomic64_add_return(2, &transaction->domain->seq_ids);
	WARN_ON(transaction->seq & 1);

	while ((entry = transaction->entries)) {
		transaction->entries = entry->transaction.next;
		fs_peer = entry->transaction.fs_peer;
		peer = bus1_fs_peer_dereference(fs_peer);

		entry->transaction.next = NULL;
		entry->transaction.fs_peer = NULL;

		mutex_lock(&peer->lock);
		bus1_queue_relink(&peer->queue, entry, transaction->seq);
		mutex_unlock(&peer->lock);

		bus1_fs_peer_release(fs_peer);
	}
}
