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
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "main.h"
#include "message.h"
#include "peer.h"
#include "tx.h"
#include "user.h"
#include "util.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

static struct bus1_queue_node *
bus1_peer_free_qnode(struct bus1_queue_node *qnode)
{
	struct bus1_message *m;
	struct bus1_handle *h;

	/*
	 * Queue-nodes are generic entities that can only be destroyed by who
	 * created them. That is, they have no embedded release callback.
	 * Instead, we must detect them by type. Since the queue logic is kept
	 * generic, it cannot provide this helper. Instead, we have this small
	 * destructor here, which simply dispatches to the correct handler.
	 */

	if (qnode) {
		switch (bus1_queue_node_get_type(qnode)) {
		case BUS1_MSG_DATA:
			m = container_of(qnode, struct bus1_message, qnode);
			bus1_message_unref(m);
			break;
		case BUS1_MSG_NODE_DESTROY:
		case BUS1_MSG_NODE_RELEASE:
			h = container_of(qnode, struct bus1_handle, qnode);
			bus1_handle_unref(h);
			break;
		case BUS1_MSG_NONE:
		default:
			WARN(1, "Unknown message type\n");
			break;
		}
	}

	return NULL;
}

/**
 * bus1_peer_new() - allocate new peer
 * @cred:	credentials used for accounting
 *
 * Allocate a new peer. It is immediately activated and ready for use. It is
 * not linked into any context. The caller will get exclusively access to the
 * peer object on success.
 *
 * Return: Pointer to peer, ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(const struct cred *cred)
{
	static atomic64_t peer_ids = ATOMIC64_INIT(0);
	struct bus1_peer *peer;
	struct bus1_user *user;
	int r;

	user = bus1_user_ref_by_uid(cred->uid);
	if (IS_ERR(user))
		return ERR_CAST(user);

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		bus1_user_unref(user);
		return ERR_PTR(-ENOMEM);
	}

	/* initialize constant fields */
	peer->id = atomic64_inc_return(&peer_ids);
	peer->flags = 0;
	peer->user = user;
	peer->debugdir = NULL;
	init_waitqueue_head(&peer->waitq);
	bus1_active_init(&peer->active);

	/* initialize data section */
	mutex_init(&peer->data.lock);
	peer->data.pool = BUS1_POOL_NULL;
	bus1_queue_init(&peer->data.queue);
	bus1_user_limits_init(&peer->data.limits, peer->user);

	/* initialize peer-private section */
	mutex_init(&peer->local.lock);
	peer->local.seed = NULL;
	peer->local.map_handles = RB_ROOT;
	peer->local.handle_ids = 0;

	r = bus1_pool_init(&peer->data.pool, KBUILD_MODNAME "-peer");
	if (r < 0)
		goto error;

	if (!IS_ERR_OR_NULL(bus1_debugdir)) {
		char idstr[22];

		snprintf(idstr, sizeof(idstr), "peer-%llx", peer->id);

		peer->debugdir = debugfs_create_dir(idstr, bus1_debugdir);
		if (!peer->debugdir) {
			pr_err("cannot create debugfs dir for peer %llx\n",
			       peer->id);
		} else if (!IS_ERR_OR_NULL(peer->debugdir)) {
			bus1_debugfs_create_atomic_x("active", S_IRUGO,
						     peer->debugdir,
						     &peer->active.count);
		}
	}

	bus1_active_activate(&peer->active);
	return peer;

error:
	bus1_peer_free(peer);
	return ERR_PTR(r);
}

static void bus1_peer_flush(struct bus1_peer *peer, u64 flags)
{
	struct bus1_message *message;
	struct bus1_pool_slice *slist, *slice;
	struct bus1_queue_node *qlist, *qnode;
	struct bus1_handle *h, *safe;
	struct bus1_tx tx;
	u64 ts;
	int n;

	lockdep_assert_held(&peer->local.lock);

	bus1_tx_init(&tx, peer);

	if (flags & BUS1_PEER_RESET_FLAG_FLUSH) {
		/* protect handles on the seed */
		if (!(flags & BUS1_PEER_RESET_FLAG_FLUSH_SEED) &&
		    peer->local.seed) {
			/*
			 * XXX: When the flush operation does not ask for a
			 *      RESET of the seed, we want to protect the nodes
			 *      that were instantiated with this seed.
			 *      Right now, we do not support this, but rather
			 *      treat all nodes as local nodes. If node
			 *      injection will be supported one day, we should
			 *      make sure to drop n_user of all seed-handles to
			 *      0 here, to make sure they're skipped in the
			 *      mass-destruction below.
			 */
		}

		/* first destroy all live anchors */
		mutex_lock(&peer->data.lock);
		rbtree_postorder_for_each_entry_safe(h, safe,
						     &peer->local.map_handles,
						     rb_to_peer) {
			if (!bus1_handle_is_anchor(h) ||
			    !bus1_handle_is_live(h))
				continue;

			bus1_handle_destroy_locked(h, &tx);
		}
		mutex_unlock(&peer->data.lock);

		/* atomically commit the destruction transaction */
		ts = bus1_tx_commit(&tx);

		/* now release all user handles */
		rbtree_postorder_for_each_entry_safe(h, safe,
						     &peer->local.map_handles,
						     rb_to_peer) {
			n = atomic_xchg(&h->n_user, 0);
			bus1_handle_forget_keep(h);
			bus1_user_discharge(&peer->user->limits.n_handles,
					    &peer->data.limits.n_handles, n);

			if (bus1_handle_is_anchor(h)) {
				if (n > 1)
					bus1_handle_release_n(h, n - 1, true);
				bus1_handle_release(h, false);
			} else {
				bus1_handle_release_n(h, n, true);
			}
		}
		peer->local.map_handles = RB_ROOT;

		/* finally flush the queue and pool */
		mutex_lock(&peer->data.lock);
		qlist = bus1_queue_flush(&peer->data.queue, ts);
		mutex_unlock(&peer->data.lock);

		while ((qnode = qlist)) {
			qlist = qnode->next;
			qnode->next = NULL;
			bus1_peer_free_qnode(qnode);
		}

		slist = bus1_pool_flush(&peer->data.pool);
		while ((slice = slist)) {
			slist = slice->next;
			slice->next = NULL;
			message = container_of(slice, struct bus1_message,
					       slice);

			bus1_message_unref(message);
		}
	}

	/* drop seed if requested */
	if (flags & BUS1_PEER_RESET_FLAG_FLUSH_SEED)
		peer->local.seed = bus1_message_unref(peer->local.seed);

	bus1_tx_deinit(&tx);
}

static void bus1_peer_cleanup(struct bus1_active *a, void *userdata)
{
	struct bus1_peer *peer = container_of(a, struct bus1_peer, active);

	mutex_lock(&peer->local.lock);
	bus1_peer_flush(peer, BUS1_PEER_RESET_FLAG_FLUSH |
			      BUS1_PEER_RESET_FLAG_FLUSH_SEED);
	mutex_unlock(&peer->local.lock);
}

static int bus1_peer_disconnect(struct bus1_peer *peer)
{
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	if (!bus1_active_cleanup(&peer->active, &peer->waitq,
				 bus1_peer_cleanup, NULL))
		return -ESHUTDOWN;

	return 0;
}

/**
 * bus1_peer_free() - destroy peer
 * @peer:	peer to destroy, or NULL
 *
 * Destroy a peer object that was previously allocated via bus1_peer_new().
 * This synchronously waits for any outstanding operations on this peer to
 * finish, then releases all linked resources and deallocates the peer in an
 * rcu-delayed manner.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	/* disconnect from environment */
	bus1_peer_disconnect(peer);

	/* deinitialize peer-private section */
	WARN_ON(!RB_EMPTY_ROOT(&peer->local.map_handles));
	WARN_ON(peer->local.seed);
	mutex_destroy(&peer->local.lock);

	/* deinitialize data section */
	bus1_user_limits_deinit(&peer->data.limits);
	bus1_queue_deinit(&peer->data.queue);
	bus1_pool_deinit(&peer->data.pool);
	mutex_destroy(&peer->data.lock);

	/* deinitialize constant fields */
	debugfs_remove_recursive(peer->debugdir);
	bus1_active_deinit(&peer->active);
	peer->user = bus1_user_unref(peer->user);
	kfree_rcu(peer, rcu);

	return NULL;
}

static int bus1_peer_ioctl_peer_query(struct bus1_peer *peer,
				      unsigned long arg)
{
	struct bus1_cmd_peer_reset __user *uparam = (void __user *)arg;
	struct bus1_cmd_peer_reset param;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_QUERY) != sizeof(param));

	if (copy_from_user(&param, uparam, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags))
		return -EINVAL;

	mutex_lock(&peer->local.lock);
	param.peer_flags = 0;
	param.max_slices = peer->data.limits.max_slices;
	param.max_handles = peer->data.limits.max_handles;
	param.max_inflight_bytes = peer->data.limits.max_inflight_bytes;
	param.max_inflight_fds = peer->data.limits.max_inflight_fds;
	mutex_unlock(&peer->local.lock);

	return copy_to_user(uparam, &param, sizeof(param)) ? -EFAULT : 0;
}

static int bus1_peer_ioctl_peer_reset(struct bus1_peer *peer,
				      unsigned long arg)
{
	struct bus1_cmd_peer_reset __user *uparam = (void __user *)arg;
	struct bus1_cmd_peer_reset param;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_RESET) != sizeof(param));

	if (copy_from_user(&param, uparam, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_PEER_RESET_FLAG_FLUSH |
				     BUS1_PEER_RESET_FLAG_FLUSH_SEED)))
		return -EINVAL;
	if (unlikely(param.peer_flags != -1))
		return -EINVAL;
	if (unlikely((param.max_slices != -1 &&
		      param.max_slices > INT_MAX) ||
		     (param.max_handles != -1 &&
		      param.max_handles > INT_MAX) ||
		     (param.max_inflight_bytes != -1 &&
		      param.max_inflight_bytes > INT_MAX) ||
		     (param.max_inflight_fds != -1 &&
		      param.max_inflight_fds > INT_MAX)))
		return -EINVAL;

	mutex_lock(&peer->local.lock);

	if (param.peer_flags != -1)
		peer->flags = param.peer_flags;

	if (param.max_slices != -1) {
		atomic_add((int)param.max_slices -
			   (int)peer->data.limits.max_slices,
			   &peer->data.limits.n_slices);
		peer->data.limits.max_slices = param.max_slices;
	}

	if (param.max_handles != -1) {
		atomic_add((int)param.max_handles -
			   (int)peer->data.limits.max_handles,
			   &peer->data.limits.n_handles);
		peer->data.limits.max_handles = param.max_handles;
	}

	if (param.max_inflight_bytes != -1) {
		atomic_add((int)param.max_inflight_bytes -
			   (int)peer->data.limits.max_inflight_bytes,
			   &peer->data.limits.n_inflight_bytes);
		peer->data.limits.max_inflight_bytes = param.max_inflight_bytes;
	}

	if (param.max_inflight_fds != -1) {
		atomic_add((int)param.max_inflight_fds -
			   (int)peer->data.limits.max_inflight_fds,
			   &peer->data.limits.n_inflight_fds);
		peer->data.limits.max_inflight_fds = param.max_inflight_fds;
	}

	bus1_peer_flush(peer, param.flags);

	mutex_unlock(&peer->local.lock);

	return 0;
}

static int bus1_peer_ioctl_handle_release(struct bus1_peer *peer,
					  unsigned long arg)
{
	struct bus1_handle *h = NULL;
	bool is_new, strong = true;
	u64 id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) != sizeof(id));

	if (get_user(id, (const u64 __user *)arg))
		return -EFAULT;

	mutex_lock(&peer->local.lock);

	h = bus1_handle_import(peer, id, &is_new);
	if (IS_ERR(h)) {
		r = PTR_ERR(h);
		goto exit;
	}

	if (is_new) {
		/*
		 * A handle is non-public only if the import lazily created the
		 * node. In that case the node is live and the last reference
		 * cannot be dropped until the node is destroyed. Hence, we
		 * return EBUSY.
		 *
		 * Since we did not modify the node, and the node was lazily
		 * created, there is no point in keeping the node allocated. We
		 * simply pretend we didn't allocate it so the next operation
		 * will just do the lazy allocation again.
		 */
		bus1_handle_forget(h);
		r = -EBUSY;
		goto exit;
	}

	if (atomic_read(&h->n_user) == 1 && bus1_handle_is_anchor(h)) {
		if (bus1_handle_is_live(h)) {
			r = -EBUSY;
			goto exit;
		}

		strong = false;
	}

	WARN_ON(atomic_dec_return(&h->n_user) < 0);
	bus1_handle_forget(h);
	bus1_user_discharge(&peer->user->limits.n_handles,
			    &peer->data.limits.n_handles, 1);
	bus1_handle_release(h, strong);

	r = 0;

exit:
	mutex_unlock(&peer->local.lock);
	bus1_handle_unref(h);
	return r;
}

static int bus1_peer_transfer(struct bus1_peer *src,
			      struct bus1_peer *dst,
			      struct bus1_cmd_handle_transfer *param)
{
	struct bus1_handle *src_h = NULL, *dst_h = NULL;
	bool is_new;
	int r;

	bus1_mutex_lock2(&src->local.lock, &dst->local.lock);

	src_h = bus1_handle_import(src, param->src_handle, &is_new);
	if (IS_ERR(src_h)) {
		r = PTR_ERR(src_h);
		src_h = NULL;
		goto exit;
	}

	if (!bus1_handle_is_live(src_h)) {
		/*
		 * If @src_h has a destruction queued, we cannot guarantee that
		 * we can join the transaction. Hence, we bail out and tell the
		 * caller that the node is already destroyed.
		 *
		 * In case @src_h->anchor is on one of the peers involved, this
		 * is properly synchronized. However, if it is a 3rd party node
		 * then it might not be committed, yet.
		 *
		 * XXX: We really ought to settle on the destruction. This
		 *      requires some waitq to settle on, though.
		 */
		param->dst_handle = BUS1_HANDLE_INVALID;
		r = 0;
		goto exit;
	}

	dst_h = bus1_handle_ref_by_other(dst, src_h);
	if (!dst_h) {
		dst_h = bus1_handle_new_remote(dst, src_h);
		if (IS_ERR(dst_h)) {
			r = PTR_ERR(dst_h);
			dst_h = NULL;
			goto exit;
		}
	}

	r = bus1_user_charge(&dst->user->limits.n_handles,
			     &dst->data.limits.n_handles, 1);
	if (r < 0)
		goto exit;

	if (is_new) {
		r = bus1_user_charge(&src->user->limits.n_handles,
				     &src->data.limits.n_handles, 1);
		if (r < 0) {
			bus1_user_discharge(&dst->user->limits.n_handles,
					    &dst->data.limits.n_handles, 1);
			goto exit;
		}

		WARN_ON(src_h != bus1_handle_acquire(src_h, false));
		WARN_ON(atomic_inc_return(&src_h->n_user) != 1);
	}

	dst_h = bus1_handle_acquire(dst_h, true);
	param->dst_handle = bus1_handle_identify(dst_h);
	bus1_handle_export(dst_h);
	WARN_ON(atomic_inc_return(&dst_h->n_user) < 1);

	r = 0;

exit:
	bus1_handle_forget(src_h);
	bus1_mutex_unlock2(&src->local.lock, &dst->local.lock);
	bus1_handle_unref(dst_h);
	bus1_handle_unref(src_h);
	return r;
}

static int bus1_peer_ioctl_handle_transfer(struct bus1_peer *src,
					   unsigned long arg)
{
	struct bus1_cmd_handle_transfer __user *uparam = (void __user *)arg;
	struct bus1_cmd_handle_transfer param;
	struct bus1_peer *dst = NULL;
	struct fd dst_f;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_HANDLE_TRANSFER) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags))
		return -EINVAL;

	if (param.dst_fd != -1) {
		dst_f = fdget(param.dst_fd);
		if (!dst_f.file)
			return -EBADF;
		if (dst_f.file->f_op != &bus1_fops) {
			fdput(dst_f);
			return -EOPNOTSUPP;
		}

		dst = bus1_peer_acquire(dst_f.file->private_data);
		fdput(dst_f);
		if (!dst)
			return -ESHUTDOWN;
	}

	r = bus1_peer_transfer(src, dst ?: src, &param);
	bus1_peer_release(dst);
	if (r < 0)
		return r;

	return copy_to_user(uparam, &param, sizeof(param)) ? -EFAULT : 0;
}

static int bus1_peer_ioctl_nodes_destroy(struct bus1_peer *peer,
					 unsigned long arg)
{
	struct bus1_cmd_nodes_destroy param;
	size_t n_charge = 0, n_discharge = 0;
	struct bus1_handle *h, *list = BUS1_TAIL;
	const u64 __user *ptr_nodes;
	struct bus1_tx tx;
	bool is_new;
	u64 i, id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_NODES_DESTROY) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~BUS1_NODES_DESTROY_FLAG_RELEASE_HANDLES))
		return -EINVAL;
	if (unlikely(param.ptr_nodes != (u64)(unsigned long)param.ptr_nodes))
		return -EFAULT;

	mutex_lock(&peer->local.lock);

	bus1_tx_init(&tx, peer);
	ptr_nodes = (const u64 __user *)(unsigned long)param.ptr_nodes;

	/*
	 * We must limit the work that user-space can dispatch in one go. We
	 * use the maximum number of handles as natural limit. You cannot hit
	 * it, anyway, except if your call would fail without it as well.
	 */
	if (unlikely(param.n_nodes > peer->user->limits.max_handles)) {
		r = -EINVAL;
		goto exit;
	}

	for (i = 0; i < param.n_nodes; ++i) {
		if (get_user(id, ptr_nodes + i)) {
			r = -EFAULT;
			goto exit;
		}

		h = bus1_handle_import(peer, id, &is_new);
		if (IS_ERR(h)) {
			r = PTR_ERR(h);
			goto exit;
		}

		if (h->tlink) {
			bus1_handle_unref(h);
			r = -ENOTUNIQ;
			goto exit;
		}

		h->tlink = list;
		list = h;

		if (!bus1_handle_is_anchor(h)) {
			r = -EREMOTE;
			goto exit;
		}

		if (!bus1_handle_is_live(h)) {
			r = -ESTALE;
			goto exit;
		}

		if (is_new)
			++n_charge;
	}

	r = bus1_user_charge(&peer->user->limits.n_handles,
			     &peer->data.limits.n_handles, n_charge);
	if (r < 0)
		goto exit;

	/* nothing below this point can fail, anymore */

	mutex_lock(&peer->data.lock);
	for (h = list; h != BUS1_TAIL; h = h->tlink) {
		if (!bus1_handle_is_public(h)) {
			WARN_ON(h != bus1_handle_acquire_locked(h, false));
			WARN_ON(atomic_inc_return(&h->n_user) != 1);
		}

		bus1_handle_destroy_locked(h, &tx);
	}
	mutex_unlock(&peer->data.lock);

	bus1_tx_commit(&tx);

	while (list != BUS1_TAIL) {
		h = list;
		list = h->tlink;
		h->tlink = NULL;

		if (param.flags & BUS1_NODES_DESTROY_FLAG_RELEASE_HANDLES) {
			++n_discharge;
			if (atomic_dec_return(&h->n_user) == 0) {
				bus1_handle_forget(h);
				bus1_handle_release(h, false);
			} else {
				bus1_handle_release(h, true);
			}
		}

		bus1_handle_unref(h);
	}

	bus1_user_discharge(&peer->user->limits.n_handles,
			    &peer->data.limits.n_handles, n_discharge);

	r = 0;

exit:
	while (list != BUS1_TAIL) {
		h = list;
		list = h->tlink;
		h->tlink = NULL;

		bus1_handle_forget(h);
		bus1_handle_unref(h);
	}
	bus1_tx_deinit(&tx);
	mutex_unlock(&peer->local.lock);
	return r;
}

static int bus1_peer_ioctl_slice_release(struct bus1_peer *peer,
					 unsigned long arg)
{
	struct bus1_pool_slice *slice;
	struct bus1_message *message;
	u64 offset;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) != sizeof(offset));

	if (get_user(offset, (const u64 __user *)arg))
		return -EFAULT;

	mutex_lock(&peer->local.lock);
	mutex_lock(&peer->data.lock);
	slice = bus1_pool_slice_find_published(&peer->data.pool, offset);
	mutex_unlock(&peer->data.lock);
	if (slice)
		bus1_pool_unpublish(slice);
	mutex_unlock(&peer->local.lock);
	if (!slice)
		return -ENXIO;

	message = container_of(slice, struct bus1_message, slice);
	bus1_message_unref(message);
	return 0;
}

static struct bus1_message *bus1_peer_new_message(struct bus1_peer *peer,
						  struct bus1_factory *f,
						  u64 id)
{
	struct bus1_message *m = NULL;
	struct bus1_handle *h = NULL;
	struct bus1_peer *p = NULL;
	bool is_new;
	int r;

	h = bus1_handle_import(peer, id, &is_new);
	if (IS_ERR(h))
		return ERR_CAST(h);

	if (h->tlink) {
		r = -ENOTUNIQ;
		goto error;
	}

	if (bus1_handle_is_anchor(h))
		p = bus1_peer_acquire(peer);
	else
		p = bus1_handle_acquire_owner(h);
	if (!p) {
		r = -ESHUTDOWN;
		goto error;
	}

	m = bus1_factory_instantiate(f, h, p);
	if (IS_ERR(m)) {
		r = PTR_ERR(m);
		goto error;
	}

	/* marker to detect duplicates */
	h->tlink = BUS1_TAIL;

	/* m->dst pins the handle for us */
	bus1_handle_unref(h);

	/* merge charge into factory (which shares the lookup with us) */
	if (is_new)
		++f->n_handles_charge;

	return m;

error:
	bus1_peer_release(p);
	if (is_new)
		bus1_handle_forget(h);
	bus1_handle_unref(h);
	return ERR_PTR(r);
}

static int bus1_peer_ioctl_send(struct bus1_peer *peer,
				unsigned long arg)
{
	struct bus1_queue_node *mlist = NULL;
	struct bus1_factory *factory = NULL;
	const u64 __user *ptr_destinations;
	struct bus1_cmd_send param;
	struct bus1_message *m;
	struct bus1_peer *p;
	size_t i, n_charge = 0;
	struct bus1_tx tx;
	u8 stack[512];
	u64 id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SEND) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_SEND_FLAG_CONTINUE |
				     BUS1_SEND_FLAG_SEED)))
		return -EINVAL;

	/* check basic limits; avoids integer-overflows later on */
	if (unlikely(param.n_destinations > INT_MAX) ||
	    unlikely(param.n_vecs > UIO_MAXIOV) ||
	    unlikely(param.n_fds > BUS1_FD_MAX))
		return -EMSGSIZE;

	/* 32bit pointer validity checks */
	if (unlikely(param.ptr_destinations !=
		     (u64)(unsigned long)param.ptr_destinations) ||
	    unlikely(param.ptr_errors !=
		     (u64)(unsigned long)param.ptr_errors) ||
	    unlikely(param.ptr_vecs !=
		     (u64)(unsigned long)param.ptr_vecs) ||
	    unlikely(param.ptr_handles !=
		     (u64)(unsigned long)param.ptr_handles) ||
	    unlikely(param.ptr_fds !=
		     (u64)(unsigned long)param.ptr_fds))
		return -EFAULT;

	mutex_lock(&peer->local.lock);

	bus1_tx_init(&tx, peer);
	ptr_destinations =
		(const u64 __user *)(unsigned long)param.ptr_destinations;

	if (unlikely(param.n_destinations > peer->user->limits.max_handles)) {
		r = -EINVAL;
		goto exit;
	}

	factory = bus1_factory_new(peer, &param, stack, sizeof(stack));
	if (IS_ERR(factory)) {
		r = PTR_ERR(factory);
		factory = NULL;
		goto exit;
	}

	if (param.flags & BUS1_SEND_FLAG_SEED) {
		if (unlikely((param.flags & BUS1_SEND_FLAG_CONTINUE) ||
			     param.n_destinations)) {
			r = -EINVAL;
			goto exit;
		}

		/* XXX: set seed */
		r = -ENOTSUPP;
		goto exit;
	} else {
		for (i = 0; i < param.n_destinations; ++i) {
			if (get_user(id, ptr_destinations + i)) {
				r = -EFAULT;
				goto exit;
			}

			m = bus1_peer_new_message(peer, factory, id);
			if (IS_ERR(m)) {
				r = PTR_ERR(m);
				goto exit;
			}

			if (!bus1_handle_is_public(m->dst))
				++n_charge;

			m->qnode.next = mlist;
			mlist = &m->qnode;
		}

		r = bus1_factory_seal(factory);
		if (r < 0)
			goto exit;

		/*
		 * Now everything is prepared, charged, and pinned. Iterate
		 * each message, acquire references, and stage the message.
		 * From here on, we must not error out, anymore.
		 */

		while (mlist) {
			m = container_of(mlist, struct bus1_message, qnode);
			mlist = m->qnode.next;
			m->qnode.next = NULL;

			if (!bus1_handle_is_public(m->dst)) {
				--factory->n_handles_charge;
				WARN_ON(m->dst != bus1_handle_acquire(m->dst,
								      false));
				WARN_ON(atomic_inc_return(&m->dst->n_user)
									!= 1);
			}

			m->dst->tlink = NULL;

			/* this consumes @m and @m->qnode.owner */
			bus1_message_stage(m, &tx);
		}

		WARN_ON(factory->n_handles_charge != 0);
		bus1_tx_commit(&tx);
	}

	r = 0;

exit:
	while (mlist) {
		m = container_of(mlist, struct bus1_message, qnode);
		mlist = m->qnode.next;
		m->qnode.next = NULL;

		p = m->qnode.owner;
		m->dst->tlink = NULL;

		bus1_handle_forget(m->dst);
		bus1_message_unref(m);
		bus1_peer_release(p);
	}
	bus1_factory_free(factory);
	bus1_tx_deinit(&tx);
	mutex_unlock(&peer->local.lock);
	return r;
}

static struct bus1_queue_node *bus1_peer_peek(struct bus1_peer *peer,
					      bool *morep)
{
	struct bus1_queue_node *qnode;
	struct bus1_message *m;
	struct bus1_handle *h;
	u64 ts;

	lockdep_assert_held(&peer->local.lock);

	mutex_lock(&peer->data.lock);
	while ((qnode = bus1_queue_peek(&peer->data.queue, morep))) {
		switch (bus1_queue_node_get_type(qnode)) {
		case BUS1_MSG_DATA:
			m = container_of(qnode, struct bus1_message, qnode);
			h = m->dst->anchor;
			break;
		case BUS1_MSG_NODE_DESTROY:
		case BUS1_MSG_NODE_RELEASE:
			m = NULL;
			h = container_of(qnode, struct bus1_handle, qnode);
			break;
		case BUS1_MSG_NONE:
		default:
			mutex_unlock(&peer->data.lock);
			WARN(1, "Unknown message type\n");
			return ERR_PTR(-ENOTRECOVERABLE);
		}

		ts = bus1_queue_node_get_timestamp(qnode);
		if (ts <= peer->data.queue.flush ||
		    !bus1_handle_is_public(h) ||
		    !bus1_handle_is_live_at(h, ts)) {
			bus1_queue_remove(&peer->data.queue, &peer->waitq,
					  qnode);
			if (m) {
				mutex_unlock(&peer->data.lock);
				bus1_message_unref(m);
				mutex_lock(&peer->data.lock);
			} else {
				bus1_handle_unref(h);
			}

			continue;
		}

		if (!m)
			bus1_queue_remove(&peer->data.queue, &peer->waitq,
					  qnode);

		break;
	}
	mutex_unlock(&peer->data.lock);

	return qnode ?: ERR_PTR(-EAGAIN);
}

static int bus1_peer_ioctl_recv(struct bus1_peer *peer,
				unsigned long arg)
{
	struct bus1_queue_node *qnode = NULL;
	struct bus1_cmd_recv param;
	struct bus1_message *m;
	struct bus1_handle *h;
	unsigned int type;
	bool more = false;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_RECV) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_RECV_FLAG_SEED |
				     BUS1_RECV_FLAG_INSTALL_FDS)))
		return -EINVAL;

	mutex_lock(&peer->local.lock);

	if (unlikely(param.flags & BUS1_RECV_FLAG_SEED)) {
		if (!peer->local.seed) {
			r = -EAGAIN;
			goto exit;
		}

		qnode = &peer->local.seed->qnode;
	} else {
		qnode = bus1_peer_peek(peer, &more);
		if (IS_ERR(qnode)) {
			r = PTR_ERR(qnode);
			goto exit;
		}
	}

	type = bus1_queue_node_get_type(qnode);
	switch (type) {
	case BUS1_MSG_DATA:
		m = container_of(qnode, struct bus1_message, qnode);
		WARN_ON(m->dst->anchor->id == BUS1_HANDLE_INVALID);

		if (param.max_offset < m->slice.offset + m->slice.size) {
			r = -ERANGE;
			goto exit;
		}

		r = bus1_message_install(m,
				param.flags & BUS1_RECV_FLAG_INSTALL_FDS);
		if (r < 0)
			goto exit;

		param.msg.type = BUS1_MSG_DATA;
		param.msg.flags = m->flags;
		param.msg.destination = m->dst->anchor->id;
		param.msg.offset = m->slice.offset;
		param.msg.n_bytes = m->n_bytes;
		param.msg.n_handles = m->n_handles;
		param.msg.n_fds = m->n_files;

		if (unlikely(param.flags & BUS1_RECV_FLAG_SEED)) {
			peer->local.seed = NULL;
		} else {
			mutex_lock(&peer->data.lock);
			bus1_queue_remove(&peer->data.queue,
					  &peer->waitq, qnode);
			mutex_unlock(&peer->data.lock);
		}
		bus1_message_deinit(m);
		bus1_message_unref(m);
		break;
	case BUS1_MSG_NODE_DESTROY:
	case BUS1_MSG_NODE_RELEASE:
		h = container_of(qnode, struct bus1_handle, qnode);
		WARN_ON(h->id == BUS1_HANDLE_INVALID);

		param.msg.type = type;
		param.msg.flags = 0;
		param.msg.destination = h->id;
		param.msg.offset = BUS1_OFFSET_INVALID;
		param.msg.n_bytes = 0;
		param.msg.n_handles = 0;
		param.msg.n_fds = 0;

		bus1_handle_unref(h);
		break;
	case BUS1_MSG_NONE:
	default:
		WARN(1, "Unknown message type\n");
		r = -ENOTRECOVERABLE;
		goto exit;
	}

	if (more)
		param.msg.flags |= BUS1_MSG_FLAG_CONTINUE;

	if (copy_to_user((void __user *)arg, &param, sizeof(param)))
		r = -EFAULT;
	else
		r = 0;

exit:
	mutex_unlock(&peer->local.lock);
	return r;
}

/**
 * bus1_peer_ioctl() - handle peer ioctls
 * @file:		file the ioctl is called on
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on a peer. This expects the peer to
 * be stored in the private_data field of @file.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
long bus1_peer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct bus1_peer *peer = file->private_data;
	int r;

	/*
	 * First handle ioctls that do not require an active-reference, then
	 * all the remaining ones wrapped in an active reference.
	 */
	switch (cmd) {
	case BUS1_CMD_PEER_DISCONNECT:
		if (unlikely(arg))
			return -EINVAL;

		r = bus1_peer_disconnect(peer);
		break;
	default:
		if (!bus1_peer_acquire(peer))
			return -ESHUTDOWN;

		switch (cmd) {
		case BUS1_CMD_PEER_QUERY:
			r = bus1_peer_ioctl_peer_query(peer, arg);
			break;
		case BUS1_CMD_PEER_RESET:
			r = bus1_peer_ioctl_peer_reset(peer, arg);
			break;
		case BUS1_CMD_HANDLE_RELEASE:
			r = bus1_peer_ioctl_handle_release(peer, arg);
			break;
		case BUS1_CMD_HANDLE_TRANSFER:
			r = bus1_peer_ioctl_handle_transfer(peer, arg);
			break;
		case BUS1_CMD_NODES_DESTROY:
			r = bus1_peer_ioctl_nodes_destroy(peer, arg);
			break;
		case BUS1_CMD_SLICE_RELEASE:
			r = bus1_peer_ioctl_slice_release(peer, arg);
			break;
		case BUS1_CMD_SEND:
			r = bus1_peer_ioctl_send(peer, arg);
			break;
		case BUS1_CMD_RECV:
			r = bus1_peer_ioctl_recv(peer, arg);
			break;
		default:
			r = -ENOTTY;
			break;
		}

		bus1_peer_release(peer);
		break;
	}

	return r;
}
