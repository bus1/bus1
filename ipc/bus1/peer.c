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
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/bus1.h>
#include "domain.h"
#include "filesystem.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "util.h"

/**
 * bus1_peer_new() - create new peer
 * @param:	parameter for peer
 *
 * Allocate a new peer object with the given parameters. The peer is not linked
 * into any domain, nor is any locking required for this call.
 *
 * Return: Pointer to new peer, or ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(struct bus1_cmd_connect *param)
{
	struct bus1_peer *peer;
	int r;

	if (unlikely(param->pool_size == 0 ||
		     !IS_ALIGNED(param->pool_size, PAGE_SIZE)))
		return ERR_PTR(-EINVAL);

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	mutex_init(&peer->lock);
	peer->pool = BUS1_POOL_NULL;
	bus1_queue_init_for_peer(&peer->queue, peer);

	r = bus1_pool_create(&peer->pool, param->pool_size);
	if (r < 0)
		goto error;

	return peer;

error:
	bus1_peer_free(peer);
	return ERR_PTR(r);
}

/**
 * bus1_peer_free() - destroy peer
 * @peer:	peer to destroy, or NULL
 *
 * This destroys and deallocates a peer object, which was previously created
 * via bus1_peer_new(). The caller must make sure no-one else is accessing the
 * peer object at the same time.
 *
 * The peer-object is released in an rcu-delayed manner. That is, the object
 * will stay accessible for at least one rcu grace period.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	bus1_queue_destroy(&peer->queue);
	bus1_pool_destroy(&peer->pool);

	/*
	 * Make sure the peer object is freed in a delayed-manner. Some
	 * embedded members (like the queue) must be accessible for an entire
	 * rcu read-side critical section.
	 */
	kfree_rcu(peer, rcu);

	return NULL;
}

/**
 * bus1_peer_reset() - reset peer
 * @peer:	peer to reset
 * @id:		ID of peer
 *
 * Reset a peer object. The caller must provide the new peer ID as @id. This
 * function will flush all data on the peer, which is tagged with an ID that
 * does not match the new ID @id.
 *
 * No locking is required by the caller. However, the caller obviously must
 * make sure they own the object.
 */
void bus1_peer_reset(struct bus1_peer *peer, u64 id)
{
	mutex_lock(&peer->lock);
	/* XXX: flush outdated queue entries */
	mutex_unlock(&peer->lock);
}

static int bus1_peer_send(struct bus1_peer *peer,
			  u64 peer_id,
			  struct bus1_fs_domain *fs_domain,
			  struct bus1_domain *domain,
			  unsigned long arg,
			  bool is_compat)
{
	struct bus1_transaction *transaction = NULL;
	struct bus1_cmd_send *param;
	u64 destination;
	size_t i;
	int r;

	param = bus1_import_fixed_ioctl(arg, sizeof(*param));
	if (IS_ERR(param))
		return PTR_ERR(param);

	if (unlikely(param->flags & ~(BUS1_SEND_FLAG_IGNORE_UNKNOWN |
				      BUS1_SEND_FLAG_CONVEY_ERRORS))) {
		r = -EINVAL;
		goto exit;
	}

	/* check basic limits; avoids integer-overflows later on */
	if (unlikely(param->n_destinations > BUS1_DESTINATION_MAX) ||
	    unlikely(param->n_vecs > BUS1_VEC_MAX) ||
	    unlikely(param->n_fds > BUS1_FD_MAX)) {
		r = -EMSGSIZE;
		goto exit;
	}

	/* 32bit pointer validity checks */
	if (unlikely(param->ptr_destinations !=
		     (u64)(void __user *)param->ptr_destinations) ||
	    unlikely(param->ptr_vecs !=
		     (u64)(void __user *)param->ptr_vecs) ||
	    unlikely(param->ptr_fds !=
		     (u64)(void __user *)param->ptr_fds)) {
		r = -EFAULT;
		goto exit;
	}

	transaction = bus1_transaction_new_from_user(fs_domain, domain,
						     peer_id, param,
						     is_compat);
	if (IS_ERR(transaction)) {
		r = PTR_ERR(transaction);
		transaction = NULL;
		goto exit;
	}

	for (i = 0; i < param->n_destinations; ++i) {
		/* faults are always fatal for any transaction */
		if (get_user(destination,
			     (u64 __user *)param->ptr_destinations + i)) {
			r = -EFAULT;
			goto exit;
		}

		r = bus1_transaction_instantiate_for_id(transaction,
							destination,
							param->flags);
		if (r < 0)
			goto exit;
	}

	bus1_transaction_commit(transaction);
	r = 0;

exit:
	bus1_transaction_free(transaction);
	kfree(param);
	return r;
}

/**
 * bus1_peer_ioctl() - handle peer ioctl
 * @peer:		peer to work on
 * @peer_id:		current ID of this peer
 * @fs_domain:		parent domain handle
 * @domain:		parent domain
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 * @is_compat:		compat ioctl
 *
 * This handles the given ioctl (cmd+arg) on the passed peer @peer. The caller
 * must make sure the peer is pinned, its current ID is provided as @peer_id,
 * its parent domain handle is pinned as @fs_domain, and dereferenced as
 * @domain.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl(struct bus1_peer *peer,
		    u64 peer_id,
		    struct bus1_fs_domain *fs_domain,
		    struct bus1_domain *domain,
		    unsigned int cmd,
		    unsigned long arg,
		    bool is_compat)
{
	int r;

	switch (cmd) {
	case BUS1_CMD_FREE:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_TRACK:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_UNTRACK:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_SEND:
		r = bus1_peer_send(peer, peer_id, fs_domain, domain,
				   arg, is_compat);
		break;
	case BUS1_CMD_RECV:
		r = 0; /* XXX */
		break;
	default:
		r = -ENOTTY;
		break;
	}

	return r;
}
