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
#include <linux/completion.h>
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
 * @ref:		object ref-count
 * @n_inflight:		number of inflight references; initially -1 if
 *			unattached; >0 if live; 0 if about to be detached
 * @n_user:		number of user-visible references (shifted by -1)
 * @rb_id:		link into owning peer, based on ID
 * @rb_node:		link into owning peer, based on node pointer
 * @node:		node this handle is linked to
 * @id:			current ID of this handle
 * @holder:		holder of this node
 * @link_node:		link into the node
 * @qnode:		queue entry for destruction notification
 * @link_flush:		temporary link during flush operations of non-owners
 */
struct bus1_handle {
	struct kref ref;
	atomic_t n_inflight;
	atomic_t n_user;
	struct rb_node rb_id;
	struct rb_node rb_node;
	struct bus1_node *node;
	u64 id;
	struct bus1_peer __rcu *holder;
	struct list_head link_node;
	union {
		struct bus1_queue_node qnode;
		struct list_head link_flush;
	};
};

/**
 * struct bus1_node - node objects
 * @ref:		object ref-count
 * @timestamp:		destruction timestamp; 0 if not live yet; 1 if live;
 *			3 if selected for destruction; even timestamp if
 *			destruction is committed
 * @list_handles:	linked list of registered handles
 * @completion:		destruction wait-queue
 * @owner:		embedded handle of node owner
 */
struct bus1_node {
	struct kref ref;
	u64 timestamp;
	struct list_head list_handles;
	struct completion completion;
	struct bus1_handle owner;
};

static void bus1_node_free(struct kref *ref)
{
	struct bus1_node *node = container_of(ref, struct bus1_node, ref);

	WARN_ON(rcu_access_pointer(node->owner.holder));
	WARN_ON(!list_empty(&node->list_handles));
	WARN_ON(node->timestamp & 1);
	kfree_rcu(node, owner.qnode.rcu);
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
	RB_CLEAR_NODE(&handle->rb_id);
	RB_CLEAR_NODE(&handle->rb_node);
	handle->node = node;
	handle->id = BUS1_HANDLE_INVALID;
	rcu_assign_pointer(handle->holder, NULL);
	INIT_LIST_HEAD(&handle->link_node);
	kref_init(&handle->ref);
	atomic_set(&handle->n_inflight, -1);
	atomic_set(&handle->n_user, -1);

	kref_get(&node->ref);
}

static void bus1_handle_destroy(struct bus1_handle *handle)
{
	WARN_ON(!list_empty(&handle->link_node));
	WARN_ON(!RB_EMPTY_NODE(&handle->rb_node));
	WARN_ON(!RB_EMPTY_NODE(&handle->rb_id));
	WARN_ON(atomic_read(&handle->n_user) > -1);
	WARN_ON(atomic_read(&handle->n_inflight) > 0);
	WARN_ON(handle->holder);

	if (bus1_handle_was_attached(handle)) {
		/*
		 * If a handle was attached, then for owners the qnode is valid
		 * as long as the handle is. For non-owners, the qnode is
		 * destroyed at uninstall and turned into a flush-link instead.
		 * If a handle was never attached, the corresponding memory is
		 * never used and stays uninitialized.
		 */
		if (bus1_handle_is_owner(handle))
			bus1_queue_node_destroy(&handle->qnode);
		else
			WARN_ON(!list_empty(&handle->link_flush));
	}

	/*
	 * CAUTION: The handle might be embedded into the node. Make sure not
	 * to touch @handle after we dropped the reference.
	 */
	kref_put(&handle->node->ref, bus1_node_free);
}

static struct bus1_handle *bus1_handle_new_owner(u64 id)
{
	struct bus1_node *node;

	if ((id & ~BUS1_NODE_FLAG_ALLOCATE) != BUS1_NODE_FLAG_MANAGED)
		return ERR_PTR(-EINVAL);

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	kref_init(&node->ref);
	INIT_LIST_HEAD(&node->list_handles);
	init_completion(&node->completion);
	node->timestamp = 0;
	bus1_handle_init(&node->owner, node);

	/* node->owner owns a reference to the node, drop the initial one */
	kref_put(&node->ref, bus1_node_no_free);

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
	struct bus1_handle *handle = container_of(ref, struct bus1_handle, ref);
	bool is_owner;

	/*
	 * Owner-handles are embedded into the linked node. They own a
	 * reference to the node, effectively making their ref-count a subset
	 * of the node ref-count. bus1_handle_destroy() drops the
	 * ref-count to the node, as such, the handle itself might already be
	 * gone once it returns. Therefore, check whether the handle is an
	 * owner-handle before destroying it, and then skip releasing the
	 * memory if it is the owner handle.
	 */
	is_owner = bus1_handle_is_owner(handle);
	bus1_handle_destroy(handle);
	if (!is_owner)
		kfree_rcu(handle, qnode.rcu);
}

static struct bus1_handle *bus1_handle_ref(struct bus1_handle *handle)
{
	if (handle)
		kref_get(&handle->ref);
	return handle;
}

static struct bus1_handle *bus1_handle_unref(struct bus1_handle *handle)
{
	if (handle)
		kref_put(&handle->ref, bus1_handle_free);
	return NULL;
}

static void bus1_handle_assert_holder(struct bus1_handle *handle,
				      struct bus1_peer_info *peer_info)
{
	struct bus1_peer *holder;

	/* verify @peer_info is the holder of @handle */

	holder = rcu_access_pointer(handle->holder);
	WARN_ON(!holder || peer_info != bus1_peer_dereference(holder));
}

/**
 * bus1_handle_from_queue() - peek or dequeue at queued handle
 * @node:		node to operate on
 * @peer_info:		peer that owns the entry
 * @drop:		whether to drop the queue entry
 *
 * This returns the handle-id of the queued handle-notification @node.
 * @peer_info must be the holder of @node and must be locked by the caller.
 *
 * If @drop is true, @node is dequeued and destroyed. Otherwise, it is left on
 * the queue.
 *
 * Return: Handle ID, or BUS1_HANDLE_INVALID if unknown to the user.
 */
u64 bus1_handle_from_queue(struct bus1_queue_node *node,
			   struct bus1_peer_info *peer_info,
			   bool drop)
{
	struct bus1_handle *handle;
	u64 id;

	lockdep_assert_held(&peer_info->lock);

	if (WARN_ON(bus1_queue_node_get_type(node) !=
					BUS1_QUEUE_NODE_HANDLE_DESTRUCTION))
		return BUS1_HANDLE_INVALID;

	handle = container_of(node, struct bus1_handle, qnode);
	id = handle->id;

	if (drop && bus1_queue_node_is_committed(node))
		bus1_handle_unref(handle);

	return id;
}

static struct bus1_peer *
bus1_handle_lock_owner(struct bus1_handle *handle,
		       struct bus1_peer_info **infop)
{
	struct bus1_peer_info *peer_info;
	struct bus1_peer *peer;

	rcu_read_lock();
	peer = bus1_peer_acquire(rcu_dereference(handle->node->owner.holder));
	rcu_read_unlock();

	if (!peer)
		return NULL;

	peer_info = bus1_peer_dereference(peer);
	mutex_lock(&peer_info->lock);
	*infop = peer_info;
	return peer;
}

static struct bus1_peer *
bus1_handle_lock_holder(struct bus1_handle *handle,
			struct bus1_peer_info **infop)
{
	struct bus1_peer_info *peer_info;
	struct bus1_peer *peer;

	rcu_read_lock();
	peer = bus1_peer_acquire(rcu_dereference(handle->holder));
	rcu_read_unlock();

	if (!peer)
		return NULL;

	peer_info = bus1_peer_dereference(peer);
	mutex_lock(&peer_info->lock);
	*infop = peer_info;
	return peer;
}

static struct bus1_peer *
bus1_handle_unlock_peer(struct bus1_peer *peer,
			struct bus1_peer_info *peer_info)
{
	if (peer) {
		mutex_unlock(&peer_info->lock);
		bus1_peer_release(peer);
	}
	return NULL;
}

static void bus1_handle_attach_internal(struct bus1_handle *handle,
					struct bus1_peer *peer)
{
	WARN_ON(rcu_access_pointer(handle->holder));
	WARN_ON(bus1_handle_was_attached(handle));
	WARN_ON(!(handle->node->timestamp & 1));

	bus1_queue_node_init(&handle->qnode,
			     BUS1_QUEUE_NODE_HANDLE_DESTRUCTION);
	atomic_set(&handle->n_inflight, 1);
	rcu_assign_pointer(handle->holder, peer);
	list_add_tail(&handle->link_node, &handle->node->list_handles);
	bus1_handle_ref(handle);
}

static void bus1_handle_attach_owner(struct bus1_handle *handle,
				     struct bus1_peer *owner)
{
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(!list_empty(&handle->node->list_handles));
	WARN_ON(handle->node->timestamp != 0);

	/* nodes pin their owners until destroyed */
	bus1_handle_ref(handle);
	handle->node->timestamp = 1;

	bus1_handle_attach_internal(handle, owner);
}

static bool bus1_handle_attach_holder(struct bus1_handle *handle,
				      struct bus1_peer *holder)
{
	struct bus1_peer *owner;

	if (!(handle->node->timestamp & 1))
		return false;

	owner = rcu_access_pointer(handle->node->owner.holder);
	lockdep_assert_held(&bus1_peer_dereference(owner)->lock);
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

	bus1_handle_assert_holder(handle, peer_info);
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
	bus1_handle_assert_holder(handle, peer_info);
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
	WARN_ON(handle->node->timestamp & 1);
	WARN_ON(!list_empty(&handle->link_node));

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

	if (bus1_queue_node_is_queued(&handle->qnode)) {
		bus1_queue_remove(&peer_info->queue, &handle->qnode);
		if (bus1_queue_node_is_committed(&handle->qnode))
			bus1_handle_unref(handle);
	}
	bus1_queue_node_destroy(&handle->qnode);
	INIT_LIST_HEAD(&handle->link_flush);
}

static void bus1_node_stage_relock(struct bus1_node *node,
				   struct bus1_peer_info *peer_info,
				   struct list_head *list_notify)
{
	struct bus1_peer_info *holder_info;
	struct bus1_peer *holder;
	struct bus1_handle *h;
	u64 timestamp;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!node->owner.holder);

	if (unlikely(node->timestamp > 1)) {
		if (!try_wait_for_completion(&node->completion)) {
			mutex_unlock(&peer_info->lock);
			wait_for_completion(&node->completion);
			mutex_lock(&peer_info->lock);
		}
		return;
	}

	list_del_init(&node->owner.link_node);
	node->timestamp = 3;
	timestamp = 3;

	while ((h = list_first_entry_or_null(&node->list_handles,
					     struct bus1_handle,
					     link_node))) {
		list_del_init(&h->link_node);

		mutex_unlock(&peer_info->lock);
		holder = bus1_handle_lock_holder(h, &holder_info);
		if (holder && rcu_access_pointer(h->holder)) {
			bus1_queue_sync(&holder_info->queue, timestamp);
			timestamp = bus1_queue_tick(&holder_info->queue);
			if (bus1_queue_stage(&holder_info->queue, &h->qnode,
					     timestamp - 1))
				bus1_peer_wake(holder);
			list_add(&h->link_node, list_notify);
		} else {
			bus1_handle_unref(h);
		}
		bus1_handle_unlock_peer(holder, holder_info);
		mutex_lock(&peer_info->lock);
	}

	bus1_queue_sync(&peer_info->queue, timestamp);
	timestamp = bus1_queue_tick(&peer_info->queue);

	holder = rcu_access_pointer(node->owner.holder);
	if (holder && bus1_queue_stage(&peer_info->queue, &node->owner.qnode,
				       timestamp - 1))
		bus1_peer_wake(holder);

	list_add_tail(&node->owner.link_node, list_notify);

	write_seqcount_begin(&peer_info->seqcount);
	node->timestamp = timestamp;
	write_seqcount_end(&peer_info->seqcount);

	if (atomic_read(&node->owner.n_inflight) == 0)
		bus1_handle_uninstall_owner(&node->owner, peer_info);
}

static void bus1_handle_notify(struct list_head *list_notify)
{
	struct bus1_peer_info *peer_info;
	struct bus1_handle *h;
	struct bus1_peer *peer;
	bool is_owner;

	/* sync all clocks so side-channels are ordered */
	list_for_each_entry(h, list_notify, link_node) {
		peer = bus1_handle_lock_holder(h, &peer_info);
		if (peer)
			bus1_queue_sync(&peer_info->queue,
					h->node->timestamp - 1);
		bus1_handle_unlock_peer(peer, peer_info);
	}

	/* commit all queued notifications */
	while ((h = list_first_entry_or_null(list_notify, struct bus1_handle,
					     link_node))) {
		list_del_init(&h->link_node);
		is_owner = bus1_handle_is_owner(h);

		peer = bus1_handle_lock_holder(h, &peer_info);
		if (peer &&
		    rcu_access_pointer(h->holder) &&
		    bus1_queue_node_is_queued(&h->qnode)) {
			/* steal the link-ref; now owned by the queue */
			if (bus1_queue_stage(&peer_info->queue,
					     &h->qnode,
					     h->node->timestamp))
				bus1_peer_wake(peer);
		} else {
			bus1_handle_unref(h);
		}
		bus1_handle_unlock_peer(peer, peer_info);

		if (is_owner) {
			/* nodes pin their owners until destroyed */
			complete_all(&h->node->completion);
			bus1_handle_unref(h);
		}
	}
}

static bool bus1_handle_detach_internal(struct bus1_handle *handle,
					struct bus1_peer_info *owner_info,
					struct list_head *list_notify)
{
	bool destroyed = false;

	lockdep_assert_held(&owner_info->lock);

	if (handle->node->timestamp == 1 && !list_empty(&handle->link_node)) {
		list_del_init(&handle->link_node);
		if (!bus1_handle_is_owner(handle))
			bus1_handle_unref(handle);
	}

	if (list_empty(&handle->node->list_handles)) {
		if (list_notify)
			bus1_node_stage_relock(handle->node, owner_info,
					       list_notify);
		destroyed = true;
	}

	return destroyed;
}

static bool bus1_handle_detach_owner(struct bus1_handle *handle,
				     struct bus1_peer_info *peer_info,
				     struct list_head *list_notify)
{
	WARN_ON(!bus1_handle_is_owner(handle));
	return bus1_handle_detach_internal(handle, peer_info, list_notify);
}

static bool bus1_handle_detach_holder(struct bus1_handle *handle,
				      struct list_head *list_notify)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;
	bool destroyed = false;

	WARN_ON(bus1_handle_is_owner(handle));
	WARN_ON(rcu_access_pointer(handle->holder));

	owner = bus1_handle_lock_owner(handle, &owner_info);
	if (owner)
		destroyed = bus1_handle_detach_internal(handle, owner_info,
							list_notify);
	bus1_handle_unlock_peer(owner, owner_info);

	return destroyed;
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

		mutex_lock(&peer_info->lock);
		if (handle->node->timestamp > 1) {
			handle = NULL;
		} else {
			atomic_inc(&handle->n_inflight);
			WARN_ON(list_empty(&handle->node->list_handles));
			list_add_tail(&handle->link_node,
				      &handle->node->list_handles);
		}
		mutex_unlock(&peer_info->lock);
	}
	return handle;
}

static bool bus1_handle_release_internal(struct bus1_handle *handle,
					 struct bus1_peer_info *peer_info,
					 struct list_head *list_notify)
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
			 * detached, then it is uninstalled. This might be
			 * triggered either by the destruction *or* the detach.
			 * So here we detach it, and if the node is destroyed
			 * (which might be triggered by the detach), and the
			 * destruction itself didn't uninstall it, then we
			 * uninstall the handle.
			 */
			if (bus1_handle_detach_owner(handle, peer_info,
						     list_notify) &&
			    rcu_access_pointer(handle->holder))
				bus1_handle_uninstall_owner(handle, peer_info);
		} else {
			bus1_handle_uninstall_holder(handle, peer_info);
			mutex_unlock(&peer_info->lock);
			bus1_handle_detach_holder(handle, list_notify);
			return true;
		}
	}

	return false;
}

static struct bus1_handle *
bus1_handle_release_staged(struct bus1_handle *handle,
			   struct bus1_peer_info *peer_info)
{
	/*
	 * See bus1_handle_release(). This releases a single inflight ref but
	 * requires the caller to *KNOW* that the handle is an owner handle and
	 * is already staged for destruction.
	 * Caller must hold the peer-lock and have already staged the node.
	 */
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(bus1_handle_release_internal(handle, peer_info, NULL));
	return NULL;
}

static struct bus1_handle *
bus1_handle_release_unlock(struct bus1_handle *handle,
			   struct bus1_peer_info *peer_info,
			   struct list_head *list_notify)
{
	/*
	 * See bus1_handle_release(). This expects the caller to have already
	 * locked @peer_info, and it will return with the peer unlocked.
	 */
	if (!bus1_handle_release_internal(handle, peer_info, list_notify))
		mutex_unlock(&peer_info->lock);
	return NULL;
}

static struct bus1_handle *
bus1_handle_release_relock(struct bus1_handle *handle,
			   struct bus1_peer_info *peer_info,
			   struct list_head *list_notify)
{
	/*
	 * See bus1_handle_release(). This expects the caller to have already
	 * locked @peer_info, and it will return with the peer still (or again)
	 * locked.
	 */
	if (bus1_handle_release_internal(handle, peer_info, list_notify))
		mutex_lock(&peer_info->lock);
	return NULL;
}

static struct bus1_handle *
bus1_handle_release(struct bus1_handle *handle,
		    struct bus1_peer_info *peer_info,
		    struct list_head *list_notify)
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
		bus1_handle_release_unlock(handle, peer_info, list_notify);
	}
	return NULL;
}

static bool bus1_node_order(struct bus1_node *node, u64 timestamp)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;
	unsigned int seq;
	u64 ts;

	/*
	 * Order node-destruction against @timestamp. If @node is still valid
	 * at the time of @timestamp, this returns true. Otherwise, false is
	 * returned.
	 * Note that this is only authoritative for negative answers. If you
	 * need authoritative positive answers, you need further guarantees
	 * like a locked owner+destination, or a readable queue entry.
	 */

	rcu_read_lock();
	owner = rcu_dereference(node->owner.holder);
	if (!owner || !(owner_info = rcu_dereference(owner->info))) {
		/*
		 * Owner handles are reset *after* the timestamp has been
		 * stored synchronously, and peer-info even after that. Hence,
		 * we can safely read the timestamp and all barriers are
		 * provided by rcu.
		 */
		ts = node->timestamp;
	} else {
		do {
			seq = read_seqcount_begin(&owner_info->seqcount);
			ts = node->timestamp;
		} while (read_seqcount_retry(&owner_info->seqcount, seq));
	}
	rcu_read_unlock();

	return ((ts & 1) || ts > timestamp);
}

static u64 bus1_handle_userref_publish(struct bus1_handle *handle,
				       struct bus1_peer_info *peer_info,
				       u64 timestamp,
				       bool commit)
{
	struct rb_node *n, **slot;
	struct bus1_handle *iter;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!bus1_handle_is_attached(handle));

	/*
	 * See whether @handle has a destruction timestamp set and whether it
	 * is ordered *before* @timestamp. This is authoritative _iff_ one of
	 * the following is true:
	 *
	 *  * @peer_info is the destination of a message with timestamp
	 *    @timestamp. In this case, we guarantee that a destruction syncs
	 *    on @peer_info during commit. Since we have @peer_info locked, a
	 *    comparison of the timestamps is authoritative and final.
	 *
	 *  * @peer_info is *not* the destination, but the message with
	 *    timestamp @timestamp is ready for dequeue. This means there is no
	 *    staging destruction queued before given message, as such @handle
	 *    must either be ordered *after* @timestamp, or it is fully
	 *    committed already. Hence, a comparison of timestamps is
	 *    authoritative and final.
	 *
	 * If none of these are true, the comparison is never authoritative.
	 * That is, bus1_node_order() might return false positives (but never
	 * false negatives). The caller must be aware of this.
	 */
	if (!bus1_node_order(handle->node, timestamp)) {
		if (commit)
			WARN_ON(atomic_dec_return(&handle->n_inflight) < 0);
		return BUS1_HANDLE_INVALID;
	}

	/*
	 * Try acquiring a user-visible reference. Note that those are shifted
	 * by -1 so a return of >=0 means there already was a reference. In
	 * that case, there is nothing for us to do but return. However, we
	 * must consume the inflight reference of the caller. Since we have the
	 * peer locked, we know that n_user cannot be dropped to -1 in
	 * parallel, so we can rely on it pinning an inflight reference. We can
	 * thus simply drop the inflight ref of the caller and are guaranteed
	 * that it will not be the last.
	 */
	if (atomic_read(&handle->n_user) >= 0) {
		if (commit) {
			WARN_ON(atomic_inc_return(&handle->n_user) == 0);
			WARN_ON(atomic_dec_return(&handle->n_inflight) == 0);
		}
		return handle->id;
	}

	/*
	 * We are the first to acquire a user-visible reference on the handle.
	 * Before making it visible, we must make sure the handle has a valid
	 * ID and is linked in the lookup tree. Once done, publish the user
	 * reference and return. This also consumes the inflight ref of the
	 * caller, so we do not have to release it manually (the fact that
	 * n_user is >=0 owns an inflight ref itself).
	 *
	 * If the handle was published before (i.e., still linked in the lookup
	 * tree), we must unlink it and allocate a new ID, otherwise we would
	 * confuse user-space as they never expect IDs to be re-used (even if
	 * in this case it would be the same linked node). We only re-use IDs
	 * for owner-handles, to make sure user-space can recognize them.
	 */

	write_seqcount_begin(&peer_info->seqcount);
	if (!RB_EMPTY_NODE(&handle->rb_id) && !bus1_handle_is_owner(handle)) {
		rb_erase(&handle->rb_id, &peer_info->map_handles_by_id);
		RB_CLEAR_NODE(&handle->rb_id);
		handle->id = BUS1_HANDLE_INVALID;
	}
	if (RB_EMPTY_NODE(&handle->rb_id)) {
		if (handle->id == BUS1_HANDLE_INVALID)
			handle->id = (++peer_info->handle_ids << 2) |
							BUS1_NODE_FLAG_MANAGED;
		if (commit) {
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
	}
	write_seqcount_end(&peer_info->seqcount);

	/* publish the ref to user-space; this consumes the inflight ref */
	if (commit)
		WARN_ON(atomic_inc_return(&handle->n_user) != 0);

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
		n = peer_info->map_handles_by_id.rb_node;
		while (n) {
			handle = container_of(n, struct bus1_handle, rb_id);
			if (id == handle->id) {
				if (kref_get_unless_zero(&handle->ref))
					res = handle;
				break;
			} else if (id < handle->id) {
				n = n->rb_left;
			} else /* if (id > handle->id) */ {
				n = n->rb_right;
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
		n = peer_info->map_handles_by_node.rb_node;
		while (n) {
			handle = container_of(n, struct bus1_handle, rb_node);
			if (node == handle->node) {
				if (kref_get_unless_zero(&handle->ref))
					res = handle;
				break;
			} else if (node < handle->node) {
				n = n->rb_left;
			} else /* if (node > handle->node) */ {
				n = n->rb_right;
			}
		}
	} while (read_seqcount_retry(&peer_info->seqcount, seq));
	rcu_read_unlock();

	return res;
}

/**
 * bus1_handle_pair() - XXX
 */
int bus1_handle_pair(struct bus1_peer *clone,
		     struct bus1_peer *peer,
		     u64 *node_idp,
		     u64 *handle_idp)
{
	struct bus1_peer_info *clone_info = bus1_peer_dereference(clone);
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_handle *root = NULL, *export = NULL;
	u64 id_node, id_handle;
	int r;

	/*
	 * This allocates a new node on @clone and imports a handle to it into
	 * @peer. The ID of both are then returned.
	 */

	root = bus1_handle_new_owner(BUS1_NODE_FLAG_ALLOCATE |
				     BUS1_NODE_FLAG_MANAGED);
	if (IS_ERR(root))
		return PTR_ERR(root);

	export = bus1_handle_new_holder(root->node);
	if (IS_ERR(export)) {
		r = PTR_ERR(export);
		export = NULL;
		goto exit;
	}

	if (clone_info < peer_info) {
		mutex_lock(&clone_info->lock);
		mutex_lock_nested(&peer_info->lock, 1);
	} else {
		mutex_lock(&peer_info->lock);
		mutex_lock_nested(&clone_info->lock, 1);
	}

	bus1_handle_attach_owner(root, clone);
	bus1_handle_install_owner(root);
	WARN_ON(!bus1_handle_attach_holder(export, peer));
	WARN_ON(export != bus1_handle_install_holder(export));
	id_node = bus1_handle_userref_publish(root, clone_info, 0, true);
	id_handle = bus1_handle_userref_publish(export, peer_info, 0, true);

	mutex_unlock(&clone_info->lock);
	mutex_unlock(&peer_info->lock);

	r = 0;
	*node_idp = id_node;
	*handle_idp = id_handle;

exit:
	bus1_handle_unref(export);
	bus1_handle_unref(root);
	return r;
}

/**
 * bus1_handle_release_by_id() - release a user handle
 * @peer_info:		peer to operate on
 * @id:			handle ID
 *
 * This releases a *user* visible reference to the handle with the given ID.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_release_by_id(struct bus1_peer_info *peer_info, u64 id)
{
	struct bus1_handle *handle;
	int r, n_user;

	handle = bus1_handle_find_by_id(peer_info, id);
	if (!handle)
		return -ENXIO;

	/* returns "old_value - 1", regardless whether it succeeded or not */
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
			LIST_HEAD(list_notify);
			bus1_handle_release_unlock(handle, peer_info,
						   &list_notify);
			bus1_handle_notify(&list_notify);
			r = 0;
		}
	}

	bus1_handle_unref(handle);
	return r;
}

/**
 * bus1_handle_destroy_by_id() - destroy a user handle
 * @peer_info:		peer to operate on
 * @id:			handle ID
 *
 * This destroys the underlying node of the handle with the given ID.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_handle_destroy_by_id(struct bus1_peer_info *peer_info, u64 id)
{
	struct bus1_handle *handle;
	LIST_HEAD(list_notify);
	int r;

	handle = bus1_handle_find_by_id(peer_info, id);
	if (!handle)
		return -ENXIO;

	mutex_lock(&peer_info->lock);
	if (!bus1_handle_is_owner(handle)) {
		r = -ENXIO;
	} else {
		/*
		 * If we're not the first to destroy the node, pretend the node
		 * does not exist, but still wait for the destruction to
		 * complete.
		 */
		if (handle->node->timestamp != 1)
			r = -ENXIO;
		else
			r = 0;

		bus1_node_stage_relock(handle->node, peer_info, &list_notify);
	}
	mutex_unlock(&peer_info->lock);

	bus1_handle_unref(handle);
	bus1_handle_notify(&list_notify);

	return r;
}

/**
 * bus1_handle_flush_all() - XXX
 */
void bus1_handle_flush_all(struct bus1_peer_info *peer_info)
{
	struct bus1_handle *h;
	struct rb_node *n, *next;
	LIST_HEAD(list_notify);
	LIST_HEAD(list_remote);
	bool live;

	mutex_lock(&peer_info->lock);
	for (n = rb_first(&peer_info->map_handles_by_node); n; n = next) {
		h = container_of(n, struct bus1_handle, rb_node);

		/* XXX: ignore entries with an ID higher than our start id */

		if (bus1_handle_is_owner(h)) {
			bus1_handle_ref(h);
			live = !!(h->node->timestamp & 1);
			if (live) {
				atomic_inc_return(&h->n_inflight);
				bus1_node_stage_relock(h->node, peer_info,
						       &list_notify);
			}
			next = rb_next(n);
			if (atomic_xchg(&h->n_user, -1) != -1)
				bus1_handle_release_staged(h, peer_info);
			if (live)
				bus1_handle_release_staged(h, peer_info);
			bus1_handle_unref(h);
		} else if (atomic_xchg(&h->n_user, -1) != -1 &&
			   atomic_dec_and_test(&h->n_inflight)) {
			next = rb_next(n);

			rb_erase(&h->rb_node, &peer_info->map_handles_by_node);
			RB_CLEAR_NODE(&h->rb_node); /* steal ref */

			bus1_handle_uninstall_holder(h, peer_info);
			WARN_ON(!list_empty(&h->link_flush));
			list_add(&h->link_flush, &list_remote);
		} else {
			next = rb_next(n);
		}
	}
	mutex_unlock(&peer_info->lock);

	/* for each detached remote node, we must also remote-detach it */
	while ((h = list_first_entry_or_null(&list_remote, struct bus1_handle,
					     link_flush))) {
		list_del_init(&h->link_flush);
		bus1_handle_detach_holder(h, &list_notify);
		bus1_handle_unref(h);
	}

	/* as last step, commit notifications as usual */
	bus1_handle_notify(&list_notify);
}

/**
 * bus1_handle_dest_init() - XXX
 */
void bus1_handle_dest_init(struct bus1_handle_dest *dest)
{
	dest->handle = NULL;
	dest->raw_peer = NULL;
	dest->idp = NULL;
}

/**
 * bus1_handle_dest_destroy() - XXX
 */
void bus1_handle_dest_destroy(struct bus1_handle_dest *dest,
			      struct bus1_peer_info *peer_info)
{
	LIST_HEAD(list_notify);

	if (!dest)
		return;

	if (dest->handle) {
		bus1_handle_release(dest->handle, peer_info, &list_notify);
		dest->handle = bus1_handle_unref(dest->handle);
		bus1_handle_notify(&list_notify);
	}
	if (dest->raw_peer) {
		bus1_active_lockdep_acquired(&dest->raw_peer->active);
		dest->raw_peer = bus1_peer_release(dest->raw_peer);
	}
}

/**
 * bus1_handle_dest_import() - XXX
 */
int bus1_handle_dest_import(struct bus1_handle_dest *dest,
			    struct bus1_peer *peer,
			    u64 __user *idp)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
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

		rcu_read_lock();
		dst_peer = rcu_dereference(handle->node->owner.holder);
		dst_peer = bus1_peer_acquire(dst_peer);
		rcu_read_unlock();

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
 * bus1_handle_dest_export() - XXX
 */
u64 bus1_handle_dest_export(struct bus1_handle_dest *dest,
			    struct bus1_peer_info *peer_info,
			    u64 timestamp)
{
	u64 id;

	if (WARN_ON(!dest->handle || !dest->raw_peer))
		return BUS1_HANDLE_INVALID;

	if (dest->idp) {
		WARN_ON(!bus1_handle_is_owner(dest->handle));
		/* consumes the inflight ref */
		id = bus1_handle_userref_publish(dest->handle, peer_info,
						 timestamp, true);
		dest->handle = bus1_handle_unref(dest->handle);
	} else if (!bus1_node_order(dest->handle->node, timestamp)) {
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

static void bus1_handle_batch_destroy(struct bus1_handle_batch *batch,
				      struct bus1_peer_info *peer_info)
{
	union bus1_handle_entry *e;
	LIST_HEAD(list_notify);
	size_t pos;

	if (!batch || !batch->n_entries)
		return;

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, batch) {
		if (e->handle) {
			if (bus1_handle_was_attached(e->handle))
				bus1_handle_release(e->handle, peer_info,
						    &list_notify);
			bus1_handle_unref(e->handle);
		}
	}

	bus1_handle_notify(&list_notify);

	if (unlikely(batch->n_entries > BUS1_HANDLE_BATCH_SIZE)) {
		e = batch->entries[BUS1_HANDLE_BATCH_SIZE].next;
		bus1_handle_list_free(e, batch->n_entries -
						BUS1_HANDLE_BATCH_SIZE);
	}

	batch->n_entries = 0;
	batch->n_handles = 0;
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

	if (WARN_ON(batch->n_handles > 0))
		return 0;
	if (*pos >= batch->n_entries)
		return 0;

	n = batch->n_entries - *pos;
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
 * bus1_handle_transfer_destroy() - destroy handle transfer context
 * @transfer:		transfer context to destroy, or NULL
 * @peer_info:		owning peer
 *
 * This releases all data allocated, or pinned by a handle-transfer context. If
 * NULL is passed, or if the transfer object was already destroyed, then
 * nothing is done.
 */
void bus1_handle_transfer_destroy(struct bus1_handle_transfer *transfer,
				  struct bus1_peer_info *peer_info)
{
	if (!transfer)
		return;

	/* safe to be called multiple times */
	bus1_handle_batch_destroy(&transfer->batch, peer_info);
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
		if (entry->id & BUS1_NODE_FLAG_ALLOCATE) {
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
		WARN_ON(!entry->handle);
		if (!bus1_handle_was_attached(entry->handle)) {
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
 * This calls releases all handles after they have been processes. Hence, this
 * must be the last operation on a transfer object, before it is destroyed.
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
	LIST_HEAD(list_notify);
	size_t pos;
	u64 id;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(n_ids != transfer->batch.n_handles);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, &transfer->batch) {
		WARN_ON(!entry->handle);
		if (entry->handle->id != BUS1_HANDLE_INVALID) {
			WARN_ON(!bus1_handle_was_attached(entry->handle));
			bus1_handle_release_relock(entry->handle, peer_info,
						   &list_notify);
			entry->handle = bus1_handle_unref(entry->handle);
		} else {
			WARN_ON(!bus1_handle_is_owner(entry->handle));
			id = bus1_handle_userref_publish(entry->handle,
							 peer_info, 0, false);
			if (put_user(id, ids + pos))
				return -EFAULT;
		}
	}

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, &transfer->batch) {
		if (entry->handle) {
			bus1_handle_userref_publish(entry->handle, peer_info,
						    0, true);
			/* XXX: UNLOCKED! */
			bus1_handle_release_relock(entry->handle, peer_info,
						   &list_notify);
			entry->handle = bus1_handle_unref(entry->handle);
		}
	}

	transfer->batch.n_handles = 0;
	bus1_handle_notify(&list_notify);

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
 * @inflight:		inflight context to destroy, or NULL
 * @peer_info:		owning peer
 *
 * This releases all data allocated, or pinned by an inflight-context. If NULL
 * is passed, or if the inflight context was already destroyed, then nothing is
 * done.
 */
void bus1_handle_inflight_destroy(struct bus1_handle_inflight *inflight,
				  struct bus1_peer_info *peer_info)
{
	if (!inflight)
		return;

	/* safe to be called multiple times */
	bus1_handle_batch_destroy(&inflight->batch, peer_info);
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
	struct bus1_handle *handle;
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
		WARN_ON(pos_to >= inflight->batch.n_entries);

		if (!from->handle) {
			handle = NULL;
		} else {
			handle = bus1_handle_find_by_node(peer_info,
							  from->handle->node);
			if (handle && !bus1_handle_acquire(handle, peer_info))
				handle = bus1_handle_unref(handle);
			if (!handle) {
				handle = bus1_handle_new_holder(
							from->handle->node);
				if (IS_ERR(handle))
					return PTR_ERR(handle);

				++inflight->n_new;
			}
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
 * the handles into the peer @dst. The caller must provide the used transfer
 * context and the origin peer as @transfer and @src.
 */
void bus1_handle_inflight_install(struct bus1_handle_inflight *inflight,
				  struct bus1_peer *dst)
{
	struct bus1_peer_info *dst_info, *owner_info;
	union bus1_handle_entry *e;
	struct bus1_handle *h, *t;
	struct bus1_peer *owner;
	size_t pos, n_installs;
	LIST_HEAD(list_notify);

	if (inflight->batch.n_handles < 1)
		return;

	dst_info = bus1_peer_dereference(dst);
	n_installs = inflight->n_new;

	if (inflight->n_new > 0) {
		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			h = e->handle;
			if (!h || bus1_handle_was_attached(h))
				continue;

			owner = bus1_handle_lock_owner(h, &owner_info);
			if (!owner || !bus1_handle_attach_holder(h, dst))
				e->handle = bus1_handle_unref(h);
			bus1_handle_unlock_peer(owner, owner_info);

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
				mutex_unlock(&dst_info->lock);
				bus1_handle_release(h, dst_info, &list_notify);
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

	bus1_handle_notify(&list_notify);
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
				 u64 timestamp)
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
			ids[i] = bus1_handle_userref_publish(h, peer_info,
							     timestamp, false);
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
				 u64 timestamp)
{
	union bus1_handle_entry *e;
	struct bus1_handle *h;
	size_t pos;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(inflight->batch.n_handles != inflight->batch.n_entries);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
		h = e->handle;
		if (h) {
			bus1_handle_userref_publish(h, peer_info, timestamp,
						    true);
			bus1_handle_unref(h);
		}
	}

	inflight->batch.n_handles = 0;
}
