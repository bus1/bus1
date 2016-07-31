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
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "peer.h"
#include "queue.h"

/**
 * struct bus1_handle - handle objects
 * @qnode:		embedded queue node (used for destruction notification)
 * @n_inflight:		number of inflight references; initially -1 if
 *			unattached; >0 if live; 0 if about to be detached
 * @n_user:		number of user-visible references (shifted by -1)
 * @rb_id:		link into owning peer, based on ID
 * @rb_node:		link into owning peer, based on node pointer
 * @node:		node this handle is linked to
 * @id:			current ID of this handle
 * @holder:		holder of this node
 * @link_node:		link into the node
 *
 * Handle objects represent an accessor to nodes. A handle is always owned by a
 * specific peer, and by that peer only. The peer-lock (or queue-lock
 * respectively) protects access to this handle. Effectively, handles represent
 * a connection between two peers (between the holder of the handle and the
 * owner of its linked node). Such connections can exist both ways, hence, both
 * peers are treated as equals. You cannot lock both peers at the same time.
 *
 * @ref and @n_inflight must be accessed atomically, @node is set statically
 * and pinned for the entire lifetime of the object. @n_user, @rb_id, @rb_node,
 * @id, and @holder are protected by peer-lock of the holding peer. @link_node
 * is protected by the peer-lock of the node-owner (handle->node->owner.holder,
 * which *might* be NULL if racing a node destruction).
 *
 * Handles always pin the node they're connected to, and the node can be
 * accessed freely at all times. During handle setup, two independent steps are
 * required:
 *
 *   1) Attach:
 *      The handle must be attached to the node so a node-owner can enumerate
 *      all linked handles. This required locking the peer-lock of the
 *      node-owner.
 *
 *   2) Install:
 *      The handle must be installed into the lookup-trees of the holding peer.
 *      This requires locking the peer-lock of the holder of the handle.
 *
 * Handles don't have any lock themselves, but are protected by the respective
 * peer locks of their holders. However, during teardown of a handle, the holder
 * must be cleared to NULL, which means racing accesses might be unable to
 * dereference the peer. Hence, if we detect this case, we treat the handle as
 * disconnected and rely on the context to clean the handle up properly.
 * The holder of a handle is set *before* ATTACH and cleared during UNINSTALL.
 * That is, we expect a handle to have the holder set before it is made visible
 * to any other context, but we immediately clear it at the first part of
 * destruction.
 *
 * The 2 connections of a handle (to node, and to holder) can be dropped
 * independently. The holder of a handle always has full control over its
 * lifetime. That means, only if the holder releases its last reference, or if
 * they disconnect, they will cause an uninstall of the handle. As long as a
 * holder has a reference, the handle will stay alive (but there's no guarantee
 * that its linked node is still live).
 * At the same time, the owner of a node is under full control of the node
 * lifetime. They can destroy the node at any time, causing a detach operation
 * of all linked handles (note that all handle->node pointers stay valid, but
 * the handle->link_node links are cleared).
 */
struct bus1_handle {
	struct bus1_queue_node qnode;
	atomic_t n_inflight;
	atomic_t n_user;
	struct rb_node rb_id;
	struct rb_node rb_node;
	struct bus1_node *node;
	u64 id;
	struct bus1_peer __rcu *holder;
	struct list_head link_node;
};

/**
 * enum bus1_node_bit - state flags of node objects
 * @BUS1_NODE_BIT_PERSISTENT:	Node was created as persistent node by its
 *				owner. This flag is set during node creation
 *				and must not be modified further.
 * @BUS1_NODE_BIT_ATTACHED:	Owner handle is attached to this node. This is
 *				a debug flag to verify that a node was properly
 *				initialized before it is used.
 * @BUS1_NODE_BIT_DESTROYED:	Node is about to be, or is already, destroyed.
 *				No further handles can be attached and the node
 *				destruction has a valid timestamp to order
 *				against other messages.
 */
enum bus1_node_bit {
	BUS1_NODE_BIT_PERSISTENT,
	BUS1_NODE_BIT_ATTACHED,
	BUS1_NODE_BIT_DESTROYED,
};

/**
 * struct bus1_node - node objects
 * @qnode:		embedded queue node (used for release notification)
 * @flags:		node flags, see enum bus1_node_bit
 * @timestamp:		destruction timestamp (0 if still live)
 * @list_handles:	linked list of registered handles
 * @owner:		embedded handle of node owner
 *
 * Every existing node is represented by a single bus1_node object. A node is
 * always connected to its owner, which is embedded with its own handle as
 * @owner. @ref and @flags must be accessed with atomic operations, everything
 * else is protected by the peer-lock (or queue-lock respectively) of
 * node->owner.holder.
 *
 * A node represents the context shared by all handles connected to that node.
 * The node itself is not linked into any lookup trees, nor should anyone but
 * handles take references to the node. To pin a node, always pin the handle
 * you want to use to access the node through. A bus1_node object itself does
 * not give any guarantee about node->owner, hence, you might not be able to
 * lock the required mutices.
 */
struct bus1_node {
	struct bus1_queue_node qnode;
	unsigned long flags;
	u64 timestamp;
	struct list_head list_handles;
	struct bus1_handle owner;
};

static bool bus1_node_is_destroyed(struct bus1_node *node)
{
	return test_bit(BUS1_NODE_BIT_DESTROYED, &node->flags);
}

static void bus1_node_free(struct kref *ref)
{
	struct bus1_node *node = container_of(ref, struct bus1_node, qnode.ref);

	WARN_ON(rcu_access_pointer(node->owner.holder));
	WARN_ON(!list_empty(&node->list_handles));
	WARN_ON(test_bit(BUS1_NODE_BIT_ATTACHED, &node->flags) !=
		test_bit(BUS1_NODE_BIT_DESTROYED, &node->flags));
	bus1_queue_node_destroy(&node->qnode);
	kfree_rcu(node, qnode.rcu);
}

static void bus1_node_no_free(struct kref *ref)
{
	/* no-op kref_put() callback that is used if we hold >1 reference */
	WARN(1, "Node object freed unexpectedly");
}

static bool bus1_handle_is_owner(struct bus1_handle *handle)
{
	return handle && handle == &handle->node->owner;
}

static bool bus1_handle_was_attached(struct bus1_handle *handle)
{
	/*
	 * Has this handle ever been, or still is, attached? Note that
	 * n_inflight is -1 initially, and will never become -1 again, once
	 * attached.
	 */
	return handle && atomic_read(&handle->n_inflight) >= 0;
}

static bool bus1_handle_is_attached(struct bus1_handle *handle)
{
	/* Is this handle currently attached? */
	return handle && atomic_read(&handle->n_inflight) > 0;
}

static void bus1_handle_init(struct bus1_handle *handle, struct bus1_node *node)
{
	bus1_queue_node_init(&handle->qnode, BUS1_QUEUE_NODE_HANDLE_DESTRUCTION,
			     (unsigned long)handle);
	atomic_set(&handle->n_inflight, -1);
	atomic_set(&handle->n_user, -1);
	RB_CLEAR_NODE(&handle->rb_id);
	RB_CLEAR_NODE(&handle->rb_node);
	handle->node = node;
	handle->id = BUS1_HANDLE_INVALID;
	rcu_assign_pointer(handle->holder, NULL);
	INIT_LIST_HEAD(&handle->link_node);

	kref_get(&node->qnode.ref);
}

static void bus1_handle_finish(struct bus1_handle *handle)
{
	WARN_ON(!list_empty(&handle->link_node));
	WARN_ON(!RB_EMPTY_NODE(&handle->rb_node));
	WARN_ON(!RB_EMPTY_NODE(&handle->rb_id));
	WARN_ON(atomic_read(&handle->n_user) > -1);
	WARN_ON(atomic_read(&handle->n_inflight) > 0);
	WARN_ON(handle->holder);

	bus1_queue_node_destroy(&handle->qnode);

	/*
	 * CAUTION: The handle might be embedded into the node. Make sure not
	 * to touch @handle after we dropped the reference.
	 */
	kref_put(&handle->node->qnode.ref, bus1_node_free);
}

static struct bus1_handle *bus1_handle_new_owner(u64 id)
{
	struct bus1_node *node;

	if (id & ~(BUS1_NODE_FLAG_MANAGED |
		   BUS1_NODE_FLAG_ALLOCATE |
		   BUS1_NODE_FLAG_PERSISTENT))
		return ERR_PTR(-EINVAL);
	if (!(id & BUS1_NODE_FLAG_MANAGED))
		return ERR_PTR(-EOPNOTSUPP);

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	node->flags = 0;
	node->timestamp = 0;
	INIT_LIST_HEAD(&node->list_handles);
	bus1_queue_node_init(&node->qnode, BUS1_QUEUE_NODE_HANDLE_RELEASE,
			     (unsigned long)node);
	bus1_handle_init(&node->owner, node);

	if (id & BUS1_NODE_FLAG_PERSISTENT)
		__set_bit(BUS1_NODE_BIT_PERSISTENT, &node->flags);

	/* node->owner owns a reference to the node, drop the initial one */
	kref_put(&node->qnode.ref, bus1_node_no_free);

	/* return the exclusive reference to @node->owner, and as such @node */
	return &node->owner;
}

static struct bus1_handle *bus1_handle_new_holder(struct bus1_node *node)
{
	struct bus1_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	bus1_handle_init(handle, node);
	return handle;
}

static void bus1_handle_free(struct kref *ref)
{
	struct bus1_handle *handle = container_of(ref, struct bus1_handle,
						  qnode.ref);
	bool is_owner;

	/*
	 * Owner-handles are embedded into the linked node. They own a
	 * reference to the node, effectively making their ref-count a subset
	 * of the node ref-count. bus1_handle_finish() drops the
	 * ref-count to the node, as such, the handle itself might already be
	 * gone once it returns. Therefore, check whether the handle is an
	 * owner-handle before destroying it, and then skip releasing the
	 * memory if it is the owner handle.
	 */
	is_owner = bus1_handle_is_owner(handle);
	bus1_handle_finish(handle);
	if (!is_owner)
		kfree_rcu(handle, qnode.rcu);
}

static struct bus1_handle *bus1_handle_ref(struct bus1_handle *handle)
{
	if (handle)
		kref_get(&handle->qnode.ref);
	return handle;
}

static struct bus1_handle *bus1_handle_unref(struct bus1_handle *handle)
{
	if (handle)
		kref_put(&handle->qnode.ref, bus1_handle_free);
	return NULL;
}

/**
 * bus1_handle_unref_queued() - unref queued handle
 * @qnode:		queue node to operate on, or NULL
 *
 * This returns the handle-id of the queued handle notification @qnode and
 * drops a single reference of @qnode.
 *
 * If the returned ID is required to be stable and valid, the owning peer of
 * the respective handle must be locked.
 *
 * If NULL is passed, this is a no-op and returns BUS1_HANDLE_INVALID.
 *
 * Return: Handle ID, or BUS1_HANDLE_INVALID if unknown to the user.
 */
u64 bus1_handle_unref_queued(struct bus1_queue_node *qnode)
{
	struct bus1_handle *handle;
	struct bus1_node *node;
	u64 id;

	if (!qnode)
		return BUS1_HANDLE_INVALID;

	switch (bus1_queue_node_get_type(qnode)) {
	case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
		handle = container_of(qnode, struct bus1_handle, qnode);
		id = handle->id;
		kref_put(&qnode->ref, bus1_handle_free);
		break;
	case BUS1_QUEUE_NODE_HANDLE_RELEASE:
		node = container_of(qnode, struct bus1_node, qnode);
		id = node->owner.id;
		kref_put(&qnode->ref, bus1_node_free);
		break;
	default:
		WARN(1, "Invalid queue-node type");
		id = BUS1_HANDLE_INVALID;
		break;
	}

	return id;
}

static struct bus1_peer *
bus1_handle_acquire_holder(struct bus1_handle *handle,
			   struct bus1_peer_info **infop)
{
	struct bus1_peer *peer;

	rcu_read_lock();
	peer = bus1_peer_acquire(rcu_dereference(handle->holder));
	rcu_read_unlock();
	if (peer)
		*infop = bus1_peer_dereference(peer);

	return peer;
}

static void bus1_handle_attach_internal(struct bus1_handle *handle,
					struct bus1_peer *peer)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;

	WARN_ON(rcu_access_pointer(handle->holder));
	WARN_ON(bus1_handle_was_attached(handle));
	WARN_ON(bus1_node_is_destroyed(handle->node));

	atomic_set(&handle->n_inflight, 1);
	rcu_assign_pointer(handle->holder, peer);
	list_add_tail(&handle->link_node, &handle->node->list_handles);
	bus1_handle_ref(handle);

	/*
	 * This WARN_ON and lockdep must be after the attach operation, since
	 * otherwise the holder would be unset for owner attachments.
	 */
	owner = rcu_access_pointer(handle->node->owner.holder);
	WARN_ON(!owner);
	owner_info = bus1_peer_dereference(owner);
	lockdep_assert_held(&owner_info->lock);

	/* flush any release-notification whenever a new handle is attached */
	bus1_queue_remove(&owner_info->queue, &handle->node->qnode);
}

static void bus1_handle_attach_owner(struct bus1_handle *handle,
				     struct bus1_peer *owner)
{
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(!list_empty(&handle->node->list_handles));

	/* nodes pin their owners until destroyed */
	bus1_handle_ref(handle);
	WARN_ON(test_and_set_bit(BUS1_NODE_BIT_ATTACHED, &handle->node->flags));

	bus1_handle_attach_internal(handle, owner);
}

static bool bus1_handle_attach_holder(struct bus1_handle *handle,
				      struct bus1_peer *holder)
{
	if (bus1_node_is_destroyed(handle->node))
		return false;

	WARN_ON(!test_bit(BUS1_NODE_BIT_ATTACHED, &handle->node->flags));
	WARN_ON(bus1_handle_is_owner(handle));
	bus1_handle_attach_internal(handle, holder);

	return true;
}

static struct bus1_handle *
bus1_handle_install_internal(struct bus1_handle *handle,
			     struct bus1_peer_info *peer_info)
{
	struct bus1_handle *iter, *old = NULL;
	struct rb_node *n, **slot;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!bus1_handle_was_attached(handle));
	WARN_ON(!RB_EMPTY_NODE(&handle->rb_node));

	/*
	 * The holder of the handle is locked. Lock the seqcount and try
	 * inserting the new handle into the lookup tree of the peer. Note
	 * that someone might have raced us, in case the linked node is *not*
	 * exclusively owned by this handle. Hence, first try to find a
	 * conflicting handle entry. If none is found we're fine. If a conflict
	 * is found, take a reference to it and skip the insertion. Return the
	 * conflict to the caller and let them deal with it (meaning: they
	 * unlock the peer, then release their temporary handle and switch over
	 * to the conflict).
	 */
	write_seqcount_begin(&peer_info->seqcount);
	n = NULL;
	slot = &peer_info->map_handles_by_node.rb_node;
	while (*slot) {
		n = *slot;
		iter = container_of(n, struct bus1_handle, rb_node);
		if (unlikely(handle->node == iter->node)) {
			/*
			 * Someone raced us installing a handle for the
			 * well-known node faster than we did. Drop our node
			 * and switch over to the other one.
			 */
			WARN_ON(iter->holder != handle->holder);

			old = handle;
			handle = bus1_handle_ref(iter);
			WARN_ON(atomic_inc_return(&handle->n_inflight) == 1);
			break;
		} else if (handle->node < iter->node) {
			slot = &n->rb_left;
		} else /* if (handle->node > iter->node) */ {
			slot = &n->rb_right;
		}
	}
	if (likely(!old)) {
		rb_link_node_rcu(&handle->rb_node, n, slot);
		rb_insert_color(&handle->rb_node,
				&peer_info->map_handles_by_node);
		bus1_handle_ref(handle);
	}
	write_seqcount_end(&peer_info->seqcount);

	return handle;
}

static void bus1_handle_install_owner(struct bus1_handle *handle)
{
	struct bus1_peer_info *peer_info;

	WARN_ON(!bus1_handle_is_owner(handle));
	peer_info = bus1_peer_dereference(rcu_access_pointer(handle->holder));
	WARN_ON(handle != bus1_handle_install_internal(handle, peer_info));
}

static struct bus1_handle *
bus1_handle_install_holder(struct bus1_handle *handle)
{
	struct bus1_peer_info *peer_info;

	WARN_ON(bus1_handle_is_owner(handle));
	peer_info = bus1_peer_dereference(rcu_access_pointer(handle->holder));
	return bus1_handle_install_internal(handle, peer_info);
}

static void bus1_handle_uninstall_internal(struct bus1_handle *handle,
					   struct bus1_peer_info *peer_info)
{
	lockdep_assert_held(&peer_info->lock);
	WARN_ON(atomic_read(&handle->n_inflight) > 0);

	rcu_assign_pointer(handle->holder, NULL);

	write_seqcount_begin(&peer_info->seqcount);
	if (!RB_EMPTY_NODE(&handle->rb_node)) {
		rb_erase(&handle->rb_node, &peer_info->map_handles_by_node);
		RB_CLEAR_NODE(&handle->rb_node);
		bus1_handle_unref(handle);
	}
	if (!RB_EMPTY_NODE(&handle->rb_id)) {
		rb_erase(&handle->rb_id, &peer_info->map_handles_by_id);
		RB_CLEAR_NODE(&handle->rb_id);
	}
	write_seqcount_end(&peer_info->seqcount);
}

static void bus1_handle_uninstall_owner(struct bus1_handle *handle,
					struct bus1_peer_info *peer_info)
{
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(!bus1_node_is_destroyed(handle->node));
	WARN_ON(!list_empty(&handle->node->list_handles));

	/*
	 * In case of owners, we always leave notifications queued. This
	 * guarantees that owners always know the time their node is destroyed,
	 * regardless whether they own a handle or not. This is important, as
	 * implementations must be able to track their nodes even if they're
	 * exclusively remotely held.
	 */

	bus1_handle_uninstall_internal(handle, peer_info);
}

static void bus1_handle_uninstall_holder(struct bus1_handle *handle,
					 struct bus1_peer_info *peer_info)
{
	lockdep_assert_held(&peer_info->lock);
	WARN_ON(bus1_handle_is_owner(handle));

	bus1_handle_uninstall_internal(handle, peer_info);

	/*
	 * For non-owners we always drop notifications before uninstalling a
	 * handle. We could leave them queued, but we know the peer cannot
	 * acquire another user-ref to the handle at this time. Therefore, we
	 * dequeue it so we can use the handle->qnode as a union for other
	 * state *after* a handle is uninstalled.
	 */
	bus1_queue_remove(&peer_info->queue, &handle->qnode);
}

static void bus1_node_commit_notifications(struct list_head *list_notify)
{
	struct bus1_peer_info *peer_info;
	struct bus1_handle *h;
	struct bus1_peer *peer;

	/* sync all clocks so side-channels are ordered */
	list_for_each_entry(h, list_notify, link_node) {
		peer = bus1_handle_acquire_holder(h, &peer_info);
		if (peer) {
			mutex_lock(&peer_info->queue.lock);
			bus1_queue_sync(&peer_info->queue, h->node->timestamp);
			mutex_unlock(&peer_info->queue.lock);
			bus1_peer_release(peer);
		}
	}

	/* commit all queued notifications */
	while ((h = list_first_entry_or_null(list_notify, struct bus1_handle,
					     link_node))) {
		list_del_init(&h->link_node);

		peer = bus1_handle_acquire_holder(h, &peer_info);
		if (peer) {
			bus1_queue_commit_staged(&peer_info->queue, &h->qnode,
						 h->node->timestamp);
			bus1_peer_release(peer);
		}

		/* nodes pin their owners until destroyed */
		if (bus1_handle_is_owner(h))
			bus1_handle_unref(h);

		/* drop ref owned by @list_notify */
		bus1_handle_unref(h);
	}
}

static void bus1_node_destroy(struct bus1_node *node,
			      struct bus1_peer_info *peer_info)
{
	struct bus1_peer_info *holder_info;
	struct bus1_peer *holder;
	LIST_HEAD(list_notify);
	struct bus1_handle *h;
	u64 timestamp;

	lockdep_assert_held(&peer_info->lock);

	if (bus1_node_is_destroyed(node))
		goto done;

	list_del_init(&node->owner.link_node);
	timestamp = 0;

	while ((h = list_first_entry_or_null(&node->list_handles,
					     struct bus1_handle,
					     link_node))) {
		list_del_init(&h->link_node);

		holder = bus1_handle_acquire_holder(h, &holder_info);
		if (holder) {
			mutex_lock(&holder_info->queue.lock);
			timestamp = bus1_queue_stage(&holder_info->queue,
						     &h->qnode, timestamp);
			mutex_unlock(&holder_info->queue.lock);
			list_add(&h->link_node, &list_notify);
			bus1_peer_release(holder);
		} else {
			bus1_handle_unref(h);
		}
	}

	/*
	 * Queue owner notification only if the owner was ever accessible. If
	 * it never got any ID assigned, the peer does not know about it and we
	 * better skip the notification. We still queue it on @list_notify to
	 * trigger the cleanup.
	 */
	mutex_lock(&peer_info->queue.lock);
	if (likely(!RB_EMPTY_NODE(&node->owner.rb_id)))
		timestamp = bus1_queue_stage(&peer_info->queue,
					     &node->owner.qnode, timestamp);
	else
		bus1_queue_sync(&peer_info->queue, timestamp);
	node->timestamp = bus1_queue_tick(&peer_info->queue);
	/* test_and_set_bit() provides barriers for node->timestamp */
	WARN_ON(test_and_set_bit(BUS1_NODE_BIT_DESTROYED, &node->flags));
	mutex_unlock(&peer_info->queue.lock);

	list_add_tail(&node->owner.link_node, &list_notify);
	bus1_node_commit_notifications(&list_notify);

done:
	/*
	 * If either we successfully committed the destruction, or if we waited
	 * for someone else to commit it, we must check n_inflight afterwards.
	 * If we were the last one, we must also trigger uninstall of the owner
	 * handle.
	 * Note that not all paths here are guaranteed that node->owner.holder
	 * is non-NULL, so we must check it again to avoid double uninstall.
	 */
	if (atomic_read(&node->owner.n_inflight) == 0 &&
	    rcu_access_pointer(node->owner.holder))
		bus1_handle_uninstall_owner(&node->owner, peer_info);
}

static void bus1_handle_detach_internal(struct bus1_handle *handle,
					struct bus1_peer_info *owner_info)
{
	lockdep_assert_held(&owner_info->lock);

	/*
	 * Unlink from node. If destruction is already staged, we must not
	 * touch @link_node. The destruction will clear all stale handles when
	 * done, so we can simply ignore it in that case.
	 */
	if (!bus1_node_is_destroyed(handle->node) &&
	    !list_empty(&handle->link_node)) {
		list_del_init(&handle->link_node);
		if (!bus1_handle_is_owner(handle))
			bus1_handle_unref(handle);
	}

	/*
	 * Once the last handle was detached, we queue a notification for the
	 * node owner. However, if the owner handle was never installed, we
	 * know it is inaccessible, and so we rather trigger an immediate node
	 * destruction.
	 */
	if (list_empty(&handle->node->list_handles)) {
		if (RB_EMPTY_NODE(&handle->node->owner.rb_id))
			bus1_node_destroy(handle->node, owner_info);
		else if (!bus1_node_is_destroyed(handle->node))
			bus1_queue_commit_unstaged(&owner_info->queue,
						   &handle->node->qnode);
	}
}

static void bus1_handle_detach_owner(struct bus1_handle *handle,
				     struct bus1_peer_info *peer_info)
{
	WARN_ON(!bus1_handle_is_owner(handle));
	bus1_handle_detach_internal(handle, peer_info);

	/*
	 * If a node is already destroyed, dropping the last reference will
	 * also uninstall the handle. Owner handles only stay accessible as
	 * long as their node is alive, or at least one reference is held.
	 */
	if (bus1_node_is_destroyed(handle->node) &&
	    rcu_access_pointer(handle->holder))
		bus1_handle_uninstall_owner(handle, peer_info);
}

static void bus1_handle_detach_holder(struct bus1_handle *handle)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;

	WARN_ON(bus1_handle_is_owner(handle));
	WARN_ON(rcu_access_pointer(handle->holder));

	owner = bus1_handle_acquire_holder(&handle->node->owner, &owner_info);
	if (owner) {
		mutex_lock(&owner_info->lock);
		bus1_handle_detach_internal(handle, owner_info);
		mutex_unlock(&owner_info->lock);
		bus1_peer_release(owner);
	}
}

static struct bus1_handle *
bus1_handle_acquire(struct bus1_handle *handle,
		    struct bus1_peer_info *peer_info)
{
	if (!handle || WARN_ON(!bus1_handle_was_attached(handle)))
		return NULL;

	if (!atomic_add_unless(&handle->n_inflight, 1, 0)) {
		if (!bus1_handle_is_owner(handle))
			return NULL;

		/* in case of OWNERs, we allow re-attach */
		mutex_lock(&peer_info->lock);
		if (bus1_node_is_destroyed(handle->node)) {
			handle = NULL;
		} else {
			atomic_inc(&handle->n_inflight);
			list_add_tail(&handle->link_node,
				      &handle->node->list_handles);

			/* flush any release-notification */
			bus1_queue_remove(&peer_info->queue,
					  &handle->node->qnode);
		}
		mutex_unlock(&peer_info->lock);
	}
	return handle;
}

static bool bus1_handle_release_internal(struct bus1_handle *handle,
					 struct bus1_peer_info *peer_info)
{
	/*
	 * Release a single inflight reference. This is the slow-path that
	 * expects @peer_info to be locked, and to be the holder of @handle. If
	 * this drops the last inflight reference, the handle is detached from
	 * its node. In case it was the last handle, the node is destroyed as
	 * well.
	 * This function might relock the peer lock. If this function returns
	 * with the peer-lock held (again), it returns "false". If the lock has
	 * been released and not re-taken, it returns true.
	 */

	lockdep_assert_held(&peer_info->lock);

	if (handle && atomic_dec_and_test(&handle->n_inflight)) {
		if (bus1_handle_is_owner(handle)) {
			/*
			 * An owner can be detached and re-attached many times.
			 * Only if the node destruction is committed, and it is
			 * detached, then it is uninstalled. This is always
			 * triggered by the destruction during detach. We never
			 * call it directly here.
			 */
			bus1_handle_detach_owner(handle, peer_info);
		} else {
			bus1_handle_uninstall_holder(handle, peer_info);
			mutex_unlock(&peer_info->lock);
			bus1_handle_detach_holder(handle);
			return true;
		}
	}

	return false;
}

static struct bus1_handle *
bus1_handle_release_owner(struct bus1_handle *handle,
			  struct bus1_peer_info *peer_info)
{
	/*
	 * See bus1_handle_release(). This must be called only on owner handles
	 * and guarantees that the peer-lock stays locked.
	 */
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(bus1_handle_release_internal(handle, peer_info));
	return NULL;
}

static struct bus1_handle *
bus1_handle_release_unlock(struct bus1_handle *handle,
			   struct bus1_peer_info *peer_info)
{
	/*
	 * See bus1_handle_release(). This expects the caller to have already
	 * locked @peer_info, and it will return with the peer unlocked.
	 */
	if (!bus1_handle_release_internal(handle, peer_info))
		mutex_unlock(&peer_info->lock);
	return NULL;
}

static struct bus1_handle *
bus1_handle_release(struct bus1_handle *handle,
		    struct bus1_peer_info *peer_info)
{
	/*
	 * This is the inverse of bus1_handle_acquire(). It drops a single
	 * inflight reference of the caller. If it is the last inflight
	 * reference, the handle is also detached from its node, and in case it
	 * was the last handle, the node is destroyed as well.
	 *
	 * This function might lock @peer_info in case this drops the last
	 * inflight reference.
	 */
	if (handle && !atomic_add_unless(&handle->n_inflight, -1, 1)) {
		mutex_lock(&peer_info->lock);
		bus1_handle_release_unlock(handle, peer_info);
	}
	return NULL;
}

static bool bus1_node_is_valid(struct bus1_node *node,
			       u64 timestamp,
			       unsigned long sender)
{
	/*
	 * Check whether a possible message with the passed timestamp and sender
	 * tag would be ordered *before* a possible node destruction of @node.
	 *
	 * Two scenarios are supported:
	 *
	 *   1) A message is destined at @node, in which case the message must
	 *      have been staged on the message queue of the node owner, as well
	 *      as a commit timestamp must have been acquired on the owner's
	 *      clock.
	 *      We now check whether the given message should be delivered or
	 *      not. That is, whether the destruction of @node happened before
	 *      @timestamp or not. We do this by guaranteeing that if the node
	 *      is not destroyed, yet, its destruction is guaranteed to get
	 *      committed with a higher timestamp than @timestamp (see the queue
	 *      for details why this is true). Hence, the message should be
	 *      transmitted. However, if the destruction is already committed,
	 *      we can easily compare its (timestamp, sender) tuple to order it.
	 *
	 *   2) A message carries @node as ancillary data. In that case, this
	 *      function decides whether @node was destroyed before the message
	 *      carrying it was committed, in which case an invalid handle must
	 *      be put in place.
	 *      This requires the message to be already committed *and*
	 *      dequeuable. That is, there is *no* staging entry in front of the
	 *      message. We now check whether @node has a destruction committed.
	 *      If not, we know its destruction can never be queued before the
	 *      message, hence the handle on the message receiver is valid.
	 *
	 * We rely on bus1_node_is_destroyed() to provide the required read-side
	 * barrier before we fetch @node->timestamp. See bus1_node_destroy() for
	 * the equivalent write-side barrier.
	 */

	WARN_ON(timestamp & 1);

	if (!bus1_node_is_destroyed(node))
		return true;

	return bus1_queue_compare(timestamp, sender, node->timestamp,
				  node->qnode.sender) < 0;
}

static void bus1_handle_refresh_id(struct bus1_handle *handle,
				   struct bus1_peer_info *peer_info)
{
	/*
	 * This (re-)allocates an ID for @handle to be exported to user-space.
	 * If @handle already has an ID, it is dropped and a new one is
	 * allocated. This assumes that no userref exists to @handle, yet, so
	 * any possible previous ID must not be re-used for re-publish. We don't
	 * do this for owner-handles, though. Those always keep their initial ID
	 * since we pretend they're always pinned by user-space. This also
	 * guarantees that a possible unmanaged ID provided by user-space is not
	 * changed (those can only exist for owner handles).
	 *
	 * The caller must hold the seqlock and peer-lock on @peer_info.
	 */

	if (!RB_EMPTY_NODE(&handle->rb_id) && !bus1_handle_is_owner(handle)) {
		rb_erase(&handle->rb_id, &peer_info->map_handles_by_id);
		RB_CLEAR_NODE(&handle->rb_id);
		handle->id = BUS1_HANDLE_INVALID;
	}
	if (RB_EMPTY_NODE(&handle->rb_id)) {
		if (handle->id == BUS1_HANDLE_INVALID)
			handle->id = (++peer_info->handle_ids << 2) |
							BUS1_NODE_FLAG_MANAGED;
	}
}

static u64 bus1_handle_prepare_publish(struct bus1_handle *handle,
				       struct bus1_peer_info *peer_info,
				       u64 timestamp,
				       unsigned long sender)
{
	/*
	 * This prepares @handle to be published to user-space. That is, it
	 * makes sure @handle has a valid ID assigned and is ordered properly
	 * against the tuple (@timestamp, @sender).
	 *
	 * Note that the caller must keep the peer locked between this call and
	 * the eventual publish operation, otherwise the returned ID might have
	 * changed. This is *not* the case for owner-handles, though. Their ID
	 * is valid for their entire lifetime, once assigned.
	 */

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!bus1_handle_is_attached(handle));

	if (!bus1_node_is_valid(handle->node, timestamp, sender))
		return BUS1_HANDLE_INVALID;
	if (atomic_read(&handle->n_user) >= 0)
		return handle->id;

	write_seqcount_begin(&peer_info->seqcount);
	bus1_handle_refresh_id(handle, peer_info);
	write_seqcount_end(&peer_info->seqcount);

	return handle->id;
}

static u64 bus1_handle_publish(struct bus1_handle *handle,
			       struct bus1_peer_info *peer_info,
			       u64 timestamp,
			       unsigned long sender)
{
	struct rb_node *n, **slot;
	struct bus1_handle *iter;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!bus1_handle_is_attached(handle));

	if (!bus1_node_is_valid(handle->node, timestamp, sender))
		return BUS1_HANDLE_INVALID;
	if (atomic_read(&handle->n_user) >= 0) {
		WARN_ON(atomic_inc_return(&handle->n_user) == 0);
		return handle->id;
	}

	write_seqcount_begin(&peer_info->seqcount);
	bus1_handle_refresh_id(handle, peer_info);
	if (RB_EMPTY_NODE(&handle->rb_id)) {
		n = NULL;
		slot = &peer_info->map_handles_by_id.rb_node;
		while (*slot) {
			n = *slot;
			iter = container_of(n, struct bus1_handle,
					    rb_id);
			if (handle->id < iter->id) {
				slot = &n->rb_left;
			} else /* if (handle->id >= iter->id) */ {
				WARN_ON(handle->id == iter->id);
				slot = &n->rb_right;
			}
		}
		rb_link_node_rcu(&handle->rb_id, n, slot);
		rb_insert_color(&handle->rb_id,
				&peer_info->map_handles_by_id);
	}
	write_seqcount_end(&peer_info->seqcount);

	/* publish the ref to user-space; this pins an inflight ref */
	WARN_ON(atomic_inc_return(&handle->n_user) != 0);
	WARN_ON(atomic_inc_return(&handle->n_inflight) < 2);

	return handle->id;
}

static struct bus1_handle *
bus1_handle_find_by_id(struct bus1_peer_info *peer_info, u64 id)
{
	struct bus1_handle *handle, *res = NULL;
	struct rb_node *n;
	unsigned int seq;

	rcu_read_lock();
	do {
		res = bus1_handle_unref(res);
		seq = read_seqcount_begin(&peer_info->seqcount);
		n = rcu_dereference(peer_info->map_handles_by_id.rb_node);
		while (n) {
			handle = container_of(n, struct bus1_handle, rb_id);
			if (id == handle->id) {
				if (kref_get_unless_zero(&handle->qnode.ref))
					res = handle;
				break;
			} else if (id < handle->id) {
				n = rcu_dereference(n->rb_left);
			} else /* if (id > handle->id) */ {
				n = rcu_dereference(n->rb_right);
			}
		}
	} while (read_seqcount_retry(&peer_info->seqcount, seq));
	rcu_read_unlock();

	return res;
}

static struct bus1_handle *
bus1_handle_find_by_node(struct bus1_peer_info *peer_info,
			 struct bus1_node *node)
{
	struct bus1_handle *handle, *res = NULL;
	struct rb_node *n;
	unsigned int seq;

	rcu_read_lock();
	do {
		res = bus1_handle_unref(res);
		seq = read_seqcount_begin(&peer_info->seqcount);
		n = rcu_dereference(peer_info->map_handles_by_node.rb_node);
		while (n) {
			handle = container_of(n, struct bus1_handle, rb_node);
			if (node == handle->node) {
				if (kref_get_unless_zero(&handle->qnode.ref))
					res = handle;
				break;
			} else if (node < handle->node) {
				n = rcu_dereference(n->rb_left);
			} else /* if (node > handle->node) */ {
				n = rcu_dereference(n->rb_right);
			}
		}
	} while (read_seqcount_retry(&peer_info->seqcount, seq));
	rcu_read_unlock();

	return res;
}

/**
 * bus1_handle_pair() - import handle manually into a peer
 * @peer:	node owner
 * @clone:	peer to import handle to
 * @peer_idp:	ID of node to create handle for
 * @clone_idp:	output for newly created handle ID
 *
 * This imports a handle into the peer @clone and returns its new ID via
 * @clone_idp. The node that is linked to must be given via @peer_idp (and
 * @peer must be its owner). If BUS1_NODE_FLAG_ALLOCATE is given, a new node is
 * allocated in @peer and returned in @peer_idp.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_pair(struct bus1_peer *peer,
		     struct bus1_peer *clone,
		     u64 *peer_idp,
		     u64 *clone_idp)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_peer_info *clone_info = bus1_peer_dereference(clone);
	struct bus1_peer_info *owner_info;
	struct bus1_handle *peer_handle = NULL, *clone_handle = NULL, *t;
	struct bus1_peer *owner = NULL;
	int r;

	if (*peer_idp & BUS1_NODE_FLAG_ALLOCATE) {
		peer_handle = bus1_handle_new_owner(*peer_idp);
		if (IS_ERR(peer_handle))
			return PTR_ERR(peer_handle);
	} else {
		peer_handle = bus1_handle_find_by_id(peer_info, *peer_idp);
		if (!peer_handle)
			return -ENXIO;

		if (atomic_read(&peer_handle->n_user) < 0) {
			r = -ENXIO;
			goto exit;
		}

		rcu_read_lock();
		owner = rcu_dereference(peer_handle->node->owner.holder);
		owner = bus1_peer_acquire(owner);
		rcu_read_unlock();

		if (!owner) {
			r = -ENXIO;
			goto exit;
		}

		owner_info = bus1_peer_dereference(owner);
	}

	clone_handle = bus1_handle_new_holder(peer_handle->node);
	if (IS_ERR(clone_handle)) {
		r = PTR_ERR(clone_handle);
		clone_handle = NULL;
		goto exit;
	}

	/*
	 * Now that we imported (or allocated) the original node, and allocated
	 * a fresh handle for the clone, we must attach it. If the node is new,
	 * we also attach, install, and publish it here. The attach operation
	 * on an existing node is the only operation that can fail (racing
	 * destruction). Hence, if it succeeded, nothing below can fail.
	 */
	if (owner) {
		mutex_lock(&owner_info->lock);
		r = bus1_handle_attach_holder(clone_handle, clone) ? 0 : -ENXIO;
		mutex_unlock(&owner_info->lock);
		if (r < 0)
			goto exit;
	} else {
		mutex_lock(&peer_info->lock);

		bus1_handle_attach_owner(peer_handle, peer);
		bus1_handle_install_owner(peer_handle);

		WARN_ON(!bus1_handle_attach_holder(clone_handle, clone));
		*peer_idp = bus1_handle_publish(peer_handle, peer_info, 0, 0);

		/* release the inflight-ref acquired via attach() and unlock */
		bus1_handle_release_unlock(peer_handle, peer_info);
	}

	/*
	 * Now that the handle is fully attached we must install it in the
	 * peer. This might race another install, in which case we switch to
	 * the alternative and release our own temporary handle.
	 */
	mutex_lock(&clone_info->lock);
	t = clone_handle;
	clone_handle = bus1_handle_install_holder(t);
	*clone_idp = bus1_handle_publish(clone_handle, clone_info, 0, 0);
	/* release the inflight-ref acquired via attach() and unlock */
	bus1_handle_release_unlock(clone_handle, clone_info);

	if (clone_handle != t) {
		bus1_handle_release(t, clone_info);
		bus1_handle_unref(t);
	}

	r = 0;

exit:
	bus1_handle_unref(clone_handle);
	bus1_handle_unref(peer_handle);
	bus1_peer_release(owner);
	return r;
}

/**
 * bus1_handle_release_by_id() - release a user handle
 * @peer_info:		peer to operate on
 * @idp:		pointer to handle ID
 *
 * This releases a *user* visible reference to the handle with the given ID.
 * The usual allocation rules for @idp apply. If @idp was modified, 1 is
 * returned. If @idp was not modified, 0 is returned. On error, a negative
 * error code is returned.
 *
 * Return: >=0 on success, negative error code on failure.
 */
int bus1_handle_release_by_id(struct bus1_peer *peer, u64 *idp)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_handle *handle;
	int r, n_user;

	if (*idp & BUS1_NODE_FLAG_ALLOCATE) {
		handle = bus1_handle_new_owner(*idp);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		mutex_lock(&peer_info->lock);
		bus1_handle_attach_owner(handle, peer);
		bus1_handle_install_owner(handle);
		*idp = bus1_handle_publish(handle, peer_info, 0, 0);
		WARN_ON(atomic_dec_return(&handle->n_user) != -1);
		WARN_ON(atomic_dec_return(&handle->n_inflight) < 1);
		bus1_handle_release_unlock(handle, peer_info);

		r = 1;
	} else {
		handle = bus1_handle_find_by_id(peer_info, *idp);
		if (!handle)
			return -ENXIO;

		/* returns "old_value - 1", regardless whether it succeeded */
		n_user = atomic_dec_if_positive(&handle->n_user);
		if (n_user >= 0) {
			/* DEC happened, but didn't drop to -1 */
			r = 0;
		} else if (n_user < -1) {
			/* DEC did not happen, no ref owned */
			r = -ENXIO;
		} else {
			/* DEC did not happen, try again locked */
			mutex_lock(&peer_info->lock);
			if (atomic_read(&handle->n_user) < 0) {
				mutex_unlock(&peer_info->lock);
				r = -ENXIO;
			} else if (atomic_dec_return(&handle->n_user) > -1) {
				mutex_unlock(&peer_info->lock);
				r = 0;
			} else {
				bus1_handle_release_unlock(handle, peer_info);
				r = 0;
			}
		}
	}

	bus1_handle_unref(handle);
	return r;
}

/**
 * bus1_node_destroy_by_id() - destroy a node
 * @peer_info:		peer to operate on
 * @idp:		pointer to handle ID
 *
 * This destroys the underlying node of the handle with the given ID. The usual
 * allocation rules for @idp apply. If @idp was modified, 1 is returned. If
 * @idp was not modified, 0 is returned. On error, a negative error code is
 * returned.
 *
 * Return: >=0 on success, negative error code on failure.
 */
int bus1_node_destroy_by_id(struct bus1_peer *peer, u64 *idp)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_handle *handle;
	int r;

	if (*idp & BUS1_NODE_FLAG_ALLOCATE) {
		handle = bus1_handle_new_owner(*idp);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		mutex_lock(&peer_info->lock);
		bus1_handle_attach_owner(handle, peer);
		bus1_handle_install_owner(handle);
		*idp = bus1_handle_publish(handle, peer_info, 0, 0);
		bus1_node_destroy(handle->node, peer_info);
		bus1_handle_release_unlock(handle, peer_info);

		r = 1;
	} else {
		handle = bus1_handle_find_by_id(peer_info, *idp);
		if (!handle)
			return -ENXIO;

		mutex_lock(&peer_info->lock);
		if (!bus1_handle_is_owner(handle) ||
		    bus1_node_is_destroyed(handle->node)) {
			r = -ENXIO;
		} else {
			bus1_node_destroy(handle->node, peer_info);
			r = 0;
		}
		mutex_unlock(&peer_info->lock);
	}

	bus1_handle_unref(handle);
	return r;
}

/**
 * bus1_handle_flush_all() - flush all nodes and handles of a peer
 * @peer_info:		peer to operate on
 * @final:		whether to flush persistent nodes
 *
 * This atomically destroys all nodes, and releases all handles, of the given
 * peer. Note that the destruction is atomic in all regards, but the handle
 * release is only atomic in regard to the holding peer. That is, the possible
 * effect on any remote node is not atomic, but done sequentially afterwards.
 *
 * If @final is false, persistent nodes are left untouched, otherwise, even
 * persistent nodes are destroyed.
 */
void bus1_handle_flush_all(struct bus1_peer_info *peer_info, bool final)
{
	struct bus1_handle *h;
	struct rb_node *n, *next;
	LIST_HEAD(list_remote);

	mutex_lock(&peer_info->lock);
	for (n = rb_first(&peer_info->map_handles_by_node); n; n = next) {
		h = container_of(n, struct bus1_handle, rb_node);
		next = rb_next(n);

		if (bus1_handle_is_owner(h)) {
			if (final || !test_bit(BUS1_NODE_BIT_PERSISTENT,
					       &h->node->flags)) {
				bus1_handle_ref(h);
				bus1_node_destroy(h->node, peer_info);
				if (atomic_xchg(&h->n_user, -1) != -1)
					bus1_handle_release_owner(h, peer_info);
				bus1_handle_unref(h);
			}
		} else if (atomic_xchg(&h->n_user, -1) != -1 &&
			   atomic_dec_and_test(&h->n_inflight)) {
			rb_erase(&h->rb_node, &peer_info->map_handles_by_node);
			RB_CLEAR_NODE(&h->rb_node); /* steal ref */

			bus1_handle_uninstall_holder(h, peer_info);
			WARN_ON(!RB_EMPTY_NODE(&h->qnode.rb));
			list_add(&h->qnode.link, &list_remote);
		}
	}
	mutex_unlock(&peer_info->lock);

	/* for each detached remote node, we must also remote-detach it */
	while ((h = list_first_entry_or_null(&list_remote, struct bus1_handle,
					     qnode.link))) {
		list_del(&h->qnode.link);
		RB_CLEAR_NODE(&h->qnode.rb);
		bus1_handle_detach_holder(h);
		bus1_handle_unref(h);
	}
}

/**
 * bus1_handle_dest_init() - initialize destination handle context
 * @dest:		destination context to initialize
 *
 * This initializes a destination handle context. The object is needed to
 * lookup and optionally create the destination handle held by the sender during
 * a transaction. That is, for each destination of a transaction, you need one
 * destination handle context.
 *
 * The destination handle can be imported via bus1_handle_dest_import().
 */
void bus1_handle_dest_init(struct bus1_handle_dest *dest)
{
	dest->handle = NULL;
	dest->raw_peer = NULL;
	dest->idp = NULL;
}

/**
 * bus1_handle_dest_destroy() - destroy destination handle context
 * @dest:		destination handle context to destroy, or NULL
 * @peer:info:		owning peer
 *
 * This releases all data pinned by a destiantion handle context. If Null is
 * passed, or if the destination object was already destroyed, then nothing is
 * done.
 */
void bus1_handle_dest_destroy(struct bus1_handle_dest *dest,
			      struct bus1_peer_info *peer_info)
{
	if (!dest)
		return;

	if (dest->handle) {
		bus1_handle_release(dest->handle, peer_info);
		dest->handle = bus1_handle_unref(dest->handle);
	}
	if (dest->raw_peer) {
		bus1_active_lockdep_acquired(&dest->raw_peer->active);
		dest->raw_peer = bus1_peer_release(dest->raw_peer);
	}
}

/**
 * bus1_handle_dest_import() - import destination handle
 * @dest:		destination context
 * @peer:		peer to import handles of
 * @idp:		user-space handle ID
 *
 * This imports a handle-ID from user-space (provided as @idp) into the
 * destination handle context. It then resolves it to the actual bus1_handle
 * objects, optionally creating a new one on demand.
 *
 * This can only be called once per destination handle context.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_dest_import(struct bus1_handle_dest *dest,
			    struct bus1_peer *peer,
			    u64 __user *idp)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_peer_info *dst_peer_info;
	struct bus1_handle *handle;
	struct bus1_peer *dst_peer;
	u64 id;

	if (WARN_ON(dest->handle || dest->raw_peer || dest->idp))
		return -ENOTRECOVERABLE;

	if (get_user(id, idp))
		return -EFAULT;

	if (id & BUS1_NODE_FLAG_ALLOCATE) {
		if (bus1_peer_acquire(peer))
			return -ESHUTDOWN;

		handle = bus1_handle_new_owner(id);
		if (IS_ERR(handle)) {
			bus1_peer_release(peer);
			return PTR_ERR(handle);
		}

		mutex_lock(&peer_info->lock);
		bus1_handle_attach_owner(handle, peer);
		bus1_handle_install_owner(handle);
		mutex_unlock(&peer_info->lock);

		dest->handle = handle;
		dest->raw_peer = peer;
		dest->idp = idp;
		bus1_active_lockdep_released(&peer->active);
	} else {
		handle = bus1_handle_find_by_id(peer_info, id);
		if (!handle)
			return -ENXIO;

		/*
		 * Check that user-space knows of the handle and owns a
		 * reference. This looks racy, but we care for none of the
		 * races. We just assume that at the time we checked for n_user
		 * we also atomically acquired the inflight reference. The fact
		 * that it is not atomic, does not matter.
		 */
		if (atomic_read(&handle->n_user) < 0) {
			bus1_handle_unref(handle);
			return -ENXIO;
		}

		dst_peer = bus1_handle_acquire_holder(&handle->node->owner,
						      &dst_peer_info);
		if (!dst_peer || !bus1_handle_acquire(handle, peer_info)) {
			bus1_peer_release(dst_peer);
			bus1_handle_unref(handle);
			return -ENXIO;
		}

		dest->handle = handle;
		dest->raw_peer = dst_peer;
		dest->idp = NULL;
		bus1_active_lockdep_released(&dst_peer->active);
	}

	return 0;
}

/**
 * bus1_handle_dest_export() - publish new nodes of destination context
 * @dest:		destinatino context
 * @peer_info:		owning peer of @dest
 * @timestamp:		final timestamp of message transaction
 * @commit:		whether to commit the node
 *
 * If a node was created as the destination of a transaction, we have to publish
 * a single user reference to the node and provide it back to the caller. This
 * function acquires the ID and optionally publishes the user-ref for it. Either
 * way the ID is returned, and it is up to the caller to copy it back to
 * userspace.
 *
 * The caller must hold the peer lock of @peer_info.
 *
 * Return: 0 on success, negative error code on failure.
 */
u64 bus1_handle_dest_export(struct bus1_handle_dest *dest,
			    struct bus1_peer_info *peer_info,
			    u64 timestamp,
			    unsigned long sender,
			    bool commit)
{
	u64 id;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(!dest->handle || !dest->raw_peer))
		return BUS1_HANDLE_INVALID;

	if (dest->idp) {
		WARN_ON(!bus1_handle_is_owner(dest->handle));
		if (commit)
			id = bus1_handle_publish(dest->handle, peer_info,
						 timestamp, sender);
		else
			id = bus1_handle_prepare_publish(dest->handle,
							 peer_info, timestamp,
							 sender);
	} else if (!bus1_node_is_valid(dest->handle->node, timestamp, sender)) {
		id = BUS1_HANDLE_INVALID;
	} else {
		WARN_ON(dest->handle->node->owner.id == BUS1_HANDLE_INVALID);
		id = dest->handle->node->owner.id;
	}

	return id;
}

/*
 * Handle Lists
 *
 * We support operations on large handle sets, bigger than we should allocate
 * linearly via kmalloc(). Hence, we rather use single-linked lists of
 * bus1_handle_entry arrays. Each entry in the list contains a maximum of
 * BUS1_HANDLE_BATCH_SIZE real entries. The BUS1_HANDLE_BATCH_SIZE+1'th entry
 * points to the next node in the linked list.
 *
 * bus1_handle_list_new() allocates a new list with space for @n entries. Such
 * lists can be released via bus1_handle_list_free().
 *
 * Entries are initially uninitialized. The caller has to fill them in.
 */

static void bus1_handle_list_free(union bus1_handle_entry *list, size_t n)
{
	union bus1_handle_entry *t;

	while (list && n > BUS1_HANDLE_BATCH_SIZE) {
		t = list;
		list = list[BUS1_HANDLE_BATCH_SIZE].next;
		kfree(t);
		n -= BUS1_HANDLE_BATCH_SIZE;
	}
	kfree(list);
}

static union bus1_handle_entry *bus1_handle_list_new(size_t n)
{
	union bus1_handle_entry list, *e, *slot;
	size_t remaining;

	list.next = NULL;
	slot = &list;
	remaining = n;

	while (remaining >= BUS1_HANDLE_BATCH_SIZE) {
		e = kmalloc(sizeof(*e) * (BUS1_HANDLE_BATCH_SIZE + 1),
			    GFP_KERNEL);
		if (!e)
			goto error;

		slot->next = e;
		slot = &e[BUS1_HANDLE_BATCH_SIZE];
		slot->next = NULL;

		remaining -= BUS1_HANDLE_BATCH_SIZE;
	}

	if (remaining > 0) {
		slot->next = kmalloc(sizeof(*e) * remaining, GFP_KERNEL);
		if (!slot->next)
			goto error;
	}

	return list.next;

error:
	bus1_handle_list_free(list.next, n);
	return NULL;
}

/*
 * Handle Batches
 *
 * A handle batch provides a convenience wrapper around handle lists. It embeds
 * the first node of the handle list into the batch object, but allocates the
 * remaining nodes on-demand.
 *
 * A handle-batch object is usually embedded into a parent object, and provides
 * space for a fixed number of handles (can be queried via batch->n_entries).
 * Initially, none of the entries is initialized. It is up to the user to fill
 * it with data.
 *
 * Batches can store two kinds of handles: Their IDs as entry->id, or a pinned
 * handle as entry->handle. By default it is assumed only IDs are stored, and
 * the caller can modify the batch freely. But once IDs are resolved to handles
 * and pinned in the batch, the caller must increment batch->n_handles for each
 * stored handle. This makes sure that the pinned handles are released on
 * destruction (starting at the front, up to @n_handles entries).
 *
 * Use the iterators BUS1_HANDLE_BATCH_FOREACH_ENTRY() and
 * BUS1_HANDLE_BATCH_FOREACH_HANDLE() to iterate either *all* entries, or only
 * the first entries up to the @n_handles'th entry (that is, iterate all entries
 * that have pinned handles).
 */

#define BUS1_HANDLE_BATCH_FIRST(_batch, _pos)			\
	((_pos) = 0, (_batch)->entries)

#define BUS1_HANDLE_BATCH_NEXT(_iter, _pos)			\
	((!(++(_pos) % BUS1_HANDLE_BATCH_SIZE)) ?		\
			((_iter) + 1)->next :			\
			((_iter) + 1))

#define BUS1_HANDLE_BATCH_FOREACH_ENTRY(_iter, _pos, _batch)		\
	for ((_iter) = BUS1_HANDLE_BATCH_FIRST((_batch), (_pos));	\
	     (_pos) < (_batch)->n_entries;				\
	     (_iter) = BUS1_HANDLE_BATCH_NEXT((_iter), (_pos)))

#define BUS1_HANDLE_BATCH_FOREACH_HANDLE(_iter, _pos, _batch)		\
	for ((_iter) = BUS1_HANDLE_BATCH_FIRST((_batch), (_pos));	\
	     (_pos) < (_batch)->n_handles;				\
	     (_iter) = BUS1_HANDLE_BATCH_NEXT((_iter), (_pos)))

static void bus1_handle_batch_init(struct bus1_handle_batch *batch,
				   size_t n_entries)
{
	batch->n_entries = n_entries;
	batch->n_handles = 0;
	if (n_entries >= BUS1_HANDLE_BATCH_SIZE)
		batch->entries[BUS1_HANDLE_BATCH_SIZE].next = NULL;
}

static int bus1_handle_batch_preload(struct bus1_handle_batch *batch)
{
	union bus1_handle_entry *e;

	/*
	 * If the number of stored entries fits into the static buffer, or if
	 * it was already pre-loaded, there is nothing to do.
	 */
	if (likely(batch->n_entries <= BUS1_HANDLE_BATCH_SIZE))
		return 0;
	if (batch->entries[BUS1_HANDLE_BATCH_SIZE].next)
		return 0;

	/* allocate handle-list for remaining, non-static entries */
	e = bus1_handle_list_new(batch->n_entries - BUS1_HANDLE_BATCH_SIZE);
	if (!e)
		return -ENOMEM;

	batch->entries[BUS1_HANDLE_BATCH_SIZE].next = e;
	return 0;
}

static void bus1_handle_batch_release(struct bus1_handle_batch *batch,
				      struct bus1_peer_info *peer_info)
{
	union bus1_handle_entry *e;
	size_t pos;

	if (!batch)
		return;

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, batch) {
		if (e->handle) {
			if (bus1_handle_was_attached(e->handle))
				bus1_handle_release(e->handle, peer_info);
			bus1_handle_unref(e->handle);
		}
	}

	batch->n_handles = 0;
}

static void bus1_handle_batch_destroy(struct bus1_handle_batch *batch)
{
	union bus1_handle_entry *e;

	if (!batch)
		return;

	if (unlikely(batch->n_entries > BUS1_HANDLE_BATCH_SIZE)) {
		e = batch->entries[BUS1_HANDLE_BATCH_SIZE].next;
		bus1_handle_list_free(e, batch->n_entries -
						BUS1_HANDLE_BATCH_SIZE);
	}

	WARN_ON(batch->n_handles > 0);
	batch->n_entries = 0;
}

static int bus1_handle_batch_import(struct bus1_handle_batch *batch,
				    const u64 __user *ids,
				    size_t n_ids)
{
	union bus1_handle_entry *block;

	if (WARN_ON(n_ids != batch->n_entries || batch->n_handles > 0))
		return -ENOTRECOVERABLE;

	BUILD_BUG_ON(sizeof(*block) != sizeof(*ids));

	block = batch->entries;
	while (n_ids > BUS1_HANDLE_BATCH_SIZE) {
		if (copy_from_user(block, ids,
				   BUS1_HANDLE_BATCH_SIZE * sizeof(*ids)))
			return -EFAULT;

		ids += BUS1_HANDLE_BATCH_SIZE;
		n_ids -= BUS1_HANDLE_BATCH_SIZE;
		block = block[BUS1_HANDLE_BATCH_SIZE].next;
	}

	if (n_ids > 0 && copy_from_user(block, ids, n_ids * sizeof(*ids)))
		return -EFAULT;

	return 0;
}

static size_t bus1_handle_batch_walk(struct bus1_handle_batch *batch,
				     size_t *pos,
				     union bus1_handle_entry **iter)
{
	size_t n;

	if (*pos >= batch->n_handles)
		return 0;

	n = batch->n_handles - *pos;
	if (n > BUS1_HANDLE_BATCH_SIZE)
		n = BUS1_HANDLE_BATCH_SIZE;

	if (*pos == 0)
		*iter = batch->entries;
	else
		*iter = (*iter)[BUS1_HANDLE_BATCH_SIZE].next;

	*pos += n;
	return n;
}

/**
 * bus1_handle_transfer_init() - initialize handle transfer context
 * @transfer:		transfer context to initialize
 * @n_entries:		number of handles that are transferred
 *
 * This initializes a handle-transfer context. This object is needed to lookup,
 * pin, and optionally create, the handles of the sender during a transaction.
 * That is, for each transaction, you need one handle-transfer object,
 * initialized with the number of handles to transfer.
 *
 * Handles can be imported via bus1_handle_transfer_import(). Once done,
 * the handle-inflight objects can be instantiated from it for each destination
 * of the transaction.
 *
 * The handle-transfer context embeds a handle-batch, as such must be
 * pre-allocated via bus1_handle_batch_inline_size().
 */
void bus1_handle_transfer_init(struct bus1_handle_transfer *transfer,
			       size_t n_entries)
{
	transfer->n_new = 0;
	bus1_handle_batch_init(&transfer->batch, n_entries);
}

/**
 * bus1_handle_transfer_release() - release handle transfer context
 * @transfer:		transfer context to release, or NULL
 * @peer_info:		owning peer
 *
 * This releases all handles that were pinned on the transfer context. This
 * might require locking the owning peer.
 */
void bus1_handle_transfer_release(struct bus1_handle_transfer *transfer,
				  struct bus1_peer_info *peer_info)
{
	if (transfer)
		bus1_handle_batch_release(&transfer->batch, peer_info);
}

/**
 * bus1_handle_transfer_destroy() - destroy handle transfer context
 * @transfer:		transfer context to destroy, or NULL
 *
 * This frees all allocated data of the handle-transfer context. If handles were
 * imported, the caller must call bus1_handle_transfer_release() before
 * destroying the transfer context.
 */
void bus1_handle_transfer_destroy(struct bus1_handle_transfer *transfer)
{
	if (transfer)
		bus1_handle_batch_destroy(&transfer->batch);
}

/**
 * bus1_handle_transfer_import() - import handles for transfer
 * @transfer:		transfer context
 * @peer_info:		peer to import handles of
 * @ids:		user-space array of handle IDs
 * @n_ids:		number of IDs in @ids
 *
 * This imports an array of handle-IDs from user-space (provided as @ids +
 * @n_ids) into the transfer context. It then resolves each of them to their
 * actual bus1_handle objects, optionally creating new ones on demand.
 *
 * This can only be called once per transfer context. Also, @n_ids must match
 * the size used with bus1_handle_transfer_init().
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_transfer_import(struct bus1_handle_transfer *transfer,
				struct bus1_peer_info *peer_info,
				const u64 __user *ids,
				size_t n_ids)
{
	union bus1_handle_entry *entry;
	struct bus1_handle *handle;
	size_t pos;
	int r;

	/*
	 * Import the handle IDs from user-space (@ids + @n_ids) into the
	 * handle-batch. Then resolve each of them and pin their underlying
	 * handle. If a new node is demanded, we allocate a fresh node+handle,
	 * but do *not* link it, yet. We just make sure it is allocated, so the
	 * final commit cannot fail due to OOM.
	 *
	 * Note that the batch-import refuses operation if already used, so we
	 * can rely on @n_handles to be 0.
	 */

	r = bus1_handle_batch_preload(&transfer->batch);
	if (r < 0)
		return r;

	r = bus1_handle_batch_import(&transfer->batch, ids, n_ids);
	if (r < 0)
		return r;

	BUS1_HANDLE_BATCH_FOREACH_ENTRY(entry, pos, &transfer->batch) {
		if (entry->id == BUS1_HANDLE_INVALID) {
			handle = NULL;
		} else if (entry->id & BUS1_NODE_FLAG_ALLOCATE) {
			handle = bus1_handle_new_owner(entry->id);
			if (IS_ERR(handle))
				return PTR_ERR(handle);

			++transfer->n_new;
		} else {
			handle = bus1_handle_find_by_id(peer_info, entry->id);
			if (!handle ||
			    atomic_read(&handle->n_user) < 0 ||
			    !bus1_handle_acquire(handle, peer_info)) {
				handle = bus1_handle_unref(handle);
				return -ENXIO;
			}
		}

		entry->handle = handle;
		++transfer->batch.n_handles;
	}

	return 0;
}

/**
 * bus1_handle_transfer_install() - install new nodes of transfer context
 * @transfer:		transfer context
 * @peer:		owning peer of @transfer
 *
 * After a transfer-context is imported, all the newly instantiated nodes must
 * be installed in the caller process. This function installs them and marks
 * them as done. It must be called *before* any derived inflight object is
 * installed.
 *
 * The caller must hold the peer-lock of @peer.
 */
void bus1_handle_transfer_install(struct bus1_handle_transfer *transfer,
				  struct bus1_peer *peer)
{
	union bus1_handle_entry *entry;
	size_t pos;

	lockdep_assert_held(&bus1_peer_dereference(peer)->lock);

	if (transfer->n_new < 1)
		return;

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, &transfer->batch) {
		if (entry->handle && !bus1_handle_was_attached(entry->handle)) {
			bus1_handle_attach_owner(entry->handle, peer);
			bus1_handle_install_owner(entry->handle);

			if (--transfer->n_new < 1)
				break;
		}
	}

	WARN_ON(transfer->n_new > 0);
}

/**
 * bus1_handle_transfer_export() - publish new nodes of transfer context
 * @transfer:		transfer context
 * @peer_info:		owning peer of @transfer
 * @ids:		user pointer to store IDs to
 * @n_ids:		number of IDs
 *
 * For every node that is created as part of an handle transfer, we have to
 * publish a single user reference to the node and provide it back to the
 * caller. This function both publishes those user-refs *and* directly copies
 * them over into the user-provided buffers.
 *
 * The caller must hold the peer lock of @peer_info.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_transfer_export(struct bus1_handle_transfer *transfer,
				struct bus1_peer_info *peer_info,
				u64 __user *ids,
				size_t n_ids)
{
	union bus1_handle_entry *entry;
	size_t pos;
	u64 id;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(n_ids != transfer->batch.n_handles);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, &transfer->batch) {
		if (entry->handle && entry->handle->id == BUS1_HANDLE_INVALID) {
			WARN_ON(!bus1_handle_is_owner(entry->handle));
			id = bus1_handle_prepare_publish(entry->handle,
							 peer_info, 0, 0);
			if (put_user(id, ids + pos))
				return -EFAULT;
		}
	}

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, &transfer->batch) {
		if (entry->handle &&
		    bus1_handle_is_owner(entry->handle) &&
		    RB_EMPTY_NODE(&entry->handle->rb_id))
			bus1_handle_publish(entry->handle, peer_info, 0, 0);
	}

	return 0;
}

/**
 * bus1_handle_inflight_init() - initialize inflight context
 * @inflight:		inflight context to initialize
 * @n_entries:		number of entries to store in this context
 *
 * This initializes an inflight-context to carry @n_entries handles. An
 * inflight-context is used to instantiate and commit the handles a peer
 * *receives* via a transaction. That is, it is created once for each
 * destination of a transaction, and it is instantiated from the
 * transfer-context of the transaction origin/sender.
 *
 * The inflight-context embeds a handle-batch, as such must be pre-allocated
 * via bus1_handle_batch_inline_size().
 */
void bus1_handle_inflight_init(struct bus1_handle_inflight *inflight,
			       size_t n_entries)
{
	inflight->n_new = 0;
	bus1_handle_batch_init(&inflight->batch, n_entries);
}

/**
 * bus1_handle_inflight_destroy() - destroy inflight-context
 * @inflight:		inflight context to destroy
 *
 * This destroys the inflight context. The caller must make sure to flush the
 * context before destroying it, in case any handles were imported.
 */
void bus1_handle_inflight_destroy(struct bus1_handle_inflight *inflight)
{
	bus1_handle_batch_destroy(&inflight->batch);
}

/**
 * bus1_handle_inflight_flush() - flush pinned resources
 * @inflight:		inflight context to flush
 * @peer_info:		owning peer
 *
 * This releases all handles that were pinned on the inflight context. This
 * might require locking the owning peer.
 */
void bus1_handle_inflight_flush(struct bus1_handle_inflight *inflight,
				struct bus1_peer_info *peer_info)
{
	bus1_handle_batch_release(&inflight->batch, peer_info);
}

/**
 * bus1_handle_inflight_import() - import inflight context
 * @inflight:		inflight context to instantiate
 * @peer_info:		peer info to instantiate for
 * @transfer:		transfer object to instantiate from
 *
 * Instantiate an inflight-context from an existing transfer-context. Import
 * each pinned handle from the transfer-context into the peer @peer_info,
 * creating new handles if required. All the handles are pinned in the inflight
 * context, but not committed, yet.
 *
 * This must only be called once per inflight object. Furthermore, the number
 * of handles must match the number of handles of the transfer-context.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_inflight_import(struct bus1_handle_inflight *inflight,
				struct bus1_peer_info *peer_info,
				struct bus1_handle_transfer *transfer)
{
	union bus1_handle_entry *from, *to;
	struct bus1_handle *handle, *t;
	size_t pos_from, pos_to;
	int r;

	r = bus1_handle_batch_preload(&inflight->batch);
	if (r < 0)
		return r;
	if (WARN_ON(inflight->batch.n_handles > 0))
		return -ENOTRECOVERABLE;
	if (WARN_ON(inflight->batch.n_entries != transfer->batch.n_entries))
		return -ENOTRECOVERABLE;

	to = BUS1_HANDLE_BATCH_FIRST(&inflight->batch, pos_to);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(from, pos_from, &transfer->batch) {
		t = from->handle;
		if (t) {
			handle = bus1_handle_find_by_node(peer_info, t->node);
			if (handle && !bus1_handle_acquire(handle, peer_info))
				handle = bus1_handle_unref(handle);
			if (!handle) {
				handle = bus1_handle_new_holder(t->node);
				if (IS_ERR(handle))
					return PTR_ERR(handle);

				++inflight->n_new;
			}
		} else {
			handle = NULL;
		}

		to->handle = handle;
		to = BUS1_HANDLE_BATCH_NEXT(to, pos_to);
		++inflight->batch.n_handles;
	}

	return 0;
}

/**
 * bus1_handle_inflight_install() - install inflight handles
 * @inflight:		instantiated inflight context
 * @dst:		peer @inflight is for
 *
 * After an inflight context was successfully instantiated, this will install
 * the handles into the peer @dst.
 */
void bus1_handle_inflight_install(struct bus1_handle_inflight *inflight,
				  struct bus1_peer *dst)
{
	struct bus1_peer_info *dst_info, *owner_info;
	union bus1_handle_entry *e;
	struct bus1_handle *h, *t;
	struct bus1_peer *owner;
	size_t pos, n_installs;

	if (inflight->batch.n_handles < 1)
		return;

	dst_info = bus1_peer_dereference(dst);
	n_installs = inflight->n_new;

	if (inflight->n_new > 0) {
		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			h = e->handle;
			if (!h || bus1_handle_was_attached(h))
				continue;

			owner = bus1_handle_acquire_holder(&h->node->owner,
							   &owner_info);
			if (owner) {
				mutex_lock(&owner_info->lock);
				if (!bus1_handle_attach_holder(h, dst)) {
					e->handle = bus1_handle_unref(h);
					--n_installs;
				}
				mutex_unlock(&owner_info->lock);
				bus1_peer_release(owner);
			} else {
				e->handle = bus1_handle_unref(h);
				--n_installs;
			}

			if (--inflight->n_new < 1)
				break;
		}
		WARN_ON(inflight->n_new > 0);
	}

	if (n_installs > 0) {
		mutex_lock(&dst_info->lock);
		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			h = e->handle;
			if (!h || !RB_EMPTY_NODE(&h->rb_node))
				continue;
			if (WARN_ON(!bus1_handle_was_attached(h)))
				continue;

			t = bus1_handle_install_holder(h);
			if (t != h) {
				bus1_handle_release_unlock(h, dst_info);
				bus1_handle_unref(h);
				e->handle = t;
				mutex_lock(&dst_info->lock);
			}

			if (--n_installs < 1)
				break;
		}
		mutex_unlock(&dst_info->lock);
		WARN_ON(n_installs > 0);
	}
}

/**
 * bus1_handle_inflight_walk() - walk all handle IDs
 * @inflight:		inflight context to walk
 * @peer_info:		peer info of inflight owner
 * @pos:		current iterator position
 * @iter:		opaque iterator
 * @ids:		output storage for ID block
 * @timestamp:		timestamp of the transaction
 *
 * This walks over all stored handles of @inflight, returning their IDs in
 * blocks to the caller, instantiating them if necessary. If a given handle will
 * be invalid at @timestamp, BUS1_HANDLE_INVALID is returned instead. The caller
 * must initialize @pos to 0 and pre-allocate @ids large enough to hold IDs of
 * all stored handles, but at most BUS1_HANDLE_BATCH_SIZE.
 *
 * On each call, this function advances @pos and @iter to keep track of the
 * iteration, and updates @ids with the handle IDs of the current block. It
 * returns the size of the current block, which is at most
 * BUS1_HANDLE_BATCH_SIZE.
 *
 * Once this returns 0, the iteration is finished.
 *
 * Return: Number of IDs in the next block, 0 if done.
 */
size_t bus1_handle_inflight_walk(struct bus1_handle_inflight *inflight,
				 struct bus1_peer_info *peer_info,
				 size_t *pos,
				 void **iter,
				 u64 *ids,
				 u64 timestamp,
				 unsigned long sender)
{
	union bus1_handle_entry **block = (union bus1_handle_entry **)iter;
	struct bus1_handle *h;
	size_t i, n;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(inflight->batch.n_handles != inflight->batch.n_entries))
		return 0;

	n = bus1_handle_batch_walk(&inflight->batch, pos, block);

	for (i = 0; i < n; ++i) {
		h = (*block)[i].handle;
		if (h)
			ids[i] = bus1_handle_prepare_publish(h, peer_info,
							     timestamp, sender);
		else
			ids[i] = BUS1_HANDLE_INVALID;
	}

	return n;
}

/**
 * bus1_handle_inflight_commit() - commit inflight context
 * @inflight:		inflight context to commit
 * @seq:		sequence number of transaction
 *
 * This commits a fully installed inflight context, given the timestamp of a
 * transaction. This will make sure to only transfer the actual handle if it is
 * ordered *before* the handle destruction.
 *
 * This must be called after a successful walk via bus1_handle_inflight_walk().
 * You must not release the peer-lock in-between, and the same timestamp must
 * be provided.
 */
void bus1_handle_inflight_commit(struct bus1_handle_inflight *inflight,
				 struct bus1_peer_info *peer_info,
				 u64 timestamp,
				 unsigned long sender)
{
	union bus1_handle_entry *e;
	size_t pos;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(inflight->batch.n_handles != inflight->batch.n_entries);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
		if (e->handle)
			bus1_handle_publish(e->handle, peer_info, timestamp,
					    sender);
	}
}
