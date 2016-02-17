/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/*
 * Node/Handles - Implementation Details
 *
 * (See header for high-level details, this is just about the implementation)
 *
 * Details about underlying nodes are entirely hidden in this implementation.
 * Any outside caller will only ever deal with handles!
 *
 * Both owning and non-owning handles are represented as `bus1_handle`. They
 * always have `node` pointing to the underlying node as long as they exist.
 * The node object itself `bus1_handle_node` is completely dumb. It just
 * contains a list of all linked handles (which is controlled by the owner) and
 * the transaction-id to synchronize its destruction.
 *
 * Whenever a new node is allocated, the owning handle is embedded in it. This
 * guarantees that the node owner always stays allocated until the node is
 * entirely unused. However, from the caller's perspective, the owning node and
 * non-owning node are indistinguishable. Both should be considered reference
 * counted dynamic objects.
 *
 * In the implementation, the owning handle is always considered to be part of
 * a node. Whenever you have access to a node, you can also access the owning
 * handle. As such, the node and its owning handle provide the link to the
 * owning peer. Every other handle provides the link to the respective handle
 * holder.
 *
 * Both types of links, the owner link and non-owner link, are locked by their
 * respective peer lock. They can only be access or modified by locking the
 * peer. Use RCU to pin a peer in case you don't own a reference, yet.
 * Links can be removed by their owning peer. This way, any peer can remove all
 * backlinks to itself at any time. This guarantees that the peer can be shut
 * down safely, without any dangling references. However, whenever a link is
 * shut down, the remote link needs to be released afterwards as well. This is
 * async as the remote peer (the possible other side of the handle/node
 * relationship) might unlink itself in parallel.
 *
 * For each handle, @ref represents the actual object ref-count. It must be
 * used to pin the actual memory of the handle. @n_inflight describes the
 * number of real references to this handle. Once it drops to 0, the handle
 * will be released (though stay accessible until @ref drops to 0 as well).
 * @n_user is a sub-counter of @n_inflight and is used to count the references
 * that were actually reported to the user. Users can only drop references from
 * @n_user, but not directly from @n_inflight. @n_inflight is kernel-protected
 * and used during message transactions, etc.
 *
 * All handles on a node are linked into the node. This link is protected by
 * the lock of the node-owner (handle->node->owner.holder->info->lock).
 * Additionally, all handles are linked into the rb-tree of holding peer. This
 * is obviously protected by the peer lock of the respective peer.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "peer.h"

struct bus1_handle {
	/* static data */
	struct rb_node rb_id;			/* rb into holder, by id */
	struct rb_node rb_node;			/* rb into holder, by node */
	struct bus1_handle_node *node;		/* node */
	u64 id;					/* assigned ID */

	/* mostly static data (only touched during destruction) */
	struct bus1_peer __rcu *holder;		/* holder of this id */
	union {
		struct list_head link_node;	/* link into node */
		struct rcu_head rcu;
	};

	/* non-static data */
	struct kref ref;			/* object ref-count */
	atomic_t n_inflight;			/* # of inflight users */
	atomic_t n_user;			/* # of times held by user */
};

struct bus1_handle_node {
	struct kref ref;			/* object ref-count */
	struct list_head list_handles;		/* list of handles */
	u64 transaction_id;			/* last transaction id */
	struct bus1_handle owner;		/* handle of node owner */
};

static void bus1_handle_node_free(struct kref *ref)
{
	struct bus1_handle_node *node = container_of(ref,
						     struct bus1_handle_node,
						     ref);

	WARN_ON(rcu_access_pointer(node->owner.holder));
	WARN_ON(!list_empty(&node->list_handles));
	kfree_rcu(node, owner.rcu);
}

static void bus1_handle_node_no_free(struct kref *ref)
{
	/* no-op kref_put() callback that is used if we hold >1 reference */
	WARN(1, "Node object freed unexpectedly");
}

static bool bus1_handle_is_owner(struct bus1_handle *handle)
{
	return handle && handle == &handle->node->owner;
}

static void bus1_handle_init(struct bus1_handle *handle,
			     struct bus1_handle_node *node)
{
	RB_CLEAR_NODE(&handle->rb_id);
	RB_CLEAR_NODE(&handle->rb_node);
	handle->node = node;
	handle->id = BUS1_ID_INVALID;
	rcu_assign_pointer(handle->holder, NULL);
	INIT_LIST_HEAD(&handle->link_node);
	kref_init(&handle->ref);
	atomic_set(&handle->n_inflight, -1);
	atomic_set(&handle->n_user, 0);

	kref_get(&node->ref);
}

static void bus1_handle_destroy(struct bus1_handle *handle)
{
	if (!handle)
		return;

	WARN_ON(atomic_read(&handle->n_inflight) != -1 &&
		!atomic_read(&handle->n_inflight) !=
		!atomic_read(&handle->n_user));
	WARN_ON(handle->holder);

	/*
	 * CAUTION: The handle might be embedded into the node. Make sure not
	 * to touch @handle after we dropped the reference.
	 */
	kref_put(&handle->node->ref, bus1_handle_node_free);
}

/**
 * bus1_handle_new_copy() - allocate new handle for existing node
 * @existing:		already linked handle
 *
 * This allocates a new, unlinked, detached handle for the same underlying node
 * as @existing.
 *
 * Return: Pointer to new handle, ERR_PTR on failure.
 */
struct bus1_handle *bus1_handle_new_copy(struct bus1_handle *existing)
{
	struct bus1_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	bus1_handle_init(handle, existing->node);
	return handle;
}

/**
 * bus1_handle_new() - allocate new handle for new node
 *
 * This allocates a new, unlinked, detached handle, together with a new, unused
 * node. No-one but this handle will have access to the node, until it is
 * installed.
 *
 * Return: Pointer to new handle, ERR_PTR on failure.
 */
struct bus1_handle *bus1_handle_new(void)
{
	struct bus1_handle_node *node;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	kref_init(&node->ref);
	INIT_LIST_HEAD(&node->list_handles);
	node->transaction_id = BUS1_ID_INVALID;
	bus1_handle_init(&node->owner, node);

	/* node->owner owns a reference to the node, drop the initial one */
	kref_put(&node->ref, bus1_handle_node_no_free);

	/* return the exclusive reference to @node->owner, and as such @node */
	return &node->owner;
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
		kfree_rcu(handle, rcu);
}

/**
 * bus1_handle_ref() - acquire reference
 * @handle:		handle to acquire reference to, or NULL
 *
 * Acquire a new reference to the passed handle. The caller must already own a
 * reference.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @handle is returned.
 */
struct bus1_handle *bus1_handle_ref(struct bus1_handle *handle)
{
	if (handle)
		kref_get(&handle->ref);
	return handle;
}

/**
 * bus1_handle_unref() - release reference
 * @handle:		handle to release reference of, or NULL
 *
 * Release a reference that was previously acquired via bus1_handle_ref().
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_handle *bus1_handle_unref(struct bus1_handle *handle)
{
	if (handle)
		kref_put(&handle->ref, bus1_handle_free);
	return NULL;
}

/**
 * bus1_handle_find_by_id() - find handle by its ID
 * @peer_info:		peer to operate on
 * @id:			ID to search for
 *
 * This searches @peer_info for a handle with the given local ID. If none is
 * found, NULL is returned. Otherwise, a reference is acquired and a pointer to
 * the handle is returned.
 *
 * Return: Pointer to referenced handle, or NULL if none found.
 */
struct bus1_handle *bus1_handle_find_by_id(struct bus1_peer_info *peer_info,
					   u64 id)
{
	struct bus1_handle *handle, *res = NULL;
	struct rb_node *n;
	unsigned int seq;

	rcu_read_lock();

	/*
	 * We do a raw-reader here, as such we don't block on a racing writer.
	 * The reason for that is successful lookups are always authoritative,
	 * regardless whether they race someone. Therefore, we do the blocking
	 * reader only on the second iteration, if we failed and detected a
	 * race.
	 */
	seq = raw_seqcount_begin(&peer_info->seqcount);
	do {
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

		/*
		 * If @n is set, we actually found the handle with the given
		 * ID. Hence, there is no need to retry the lookup, even if we
		 * have a racing writer. Even if @res is NULL, the negative
		 * lookup is authoritative since we know that ids are
		 * sequential and never reused.
		 *
		 * However, if the lookup was negative we must check that there
		 * is no racing writer. If there is, we now do a blocking
		 * read-side acquisition and then retry the lookup.
		 */
	} while (!n &&
		 read_seqcount_retry(&peer_info->seqcount, seq) &&
		 ((seq = read_seqcount_begin(&peer_info->seqcount)), true));

	rcu_read_unlock();

	return res;
}

/**
 * bus1_handle_find_by_node() - find handle by its node
 * @peer_info:		peer to operate on
 * @existing:		any existing handle to match on
 *
 * This searches @peer_info for a handle that is linked to the same node as
 * @existing. If none is found, NULL is returned. Otherwise, a reference is
 * acquired and a pointer to the handle is returned.
 *
 * Return: Pointer to referenced handle, or NULL if none found.
 */
struct bus1_handle *bus1_handle_find_by_node(struct bus1_peer_info *peer_info,
					     struct bus1_handle *existing)
{
	struct bus1_handle *handle, *res = NULL;
	struct rb_node *n;
	unsigned int seq;

	rcu_read_lock();

	/*
	 * Similar to bus1_node_handle_find_by_id(), the first iteration can
	 * safely be a raw non-blocking reader, as we expect this to succeed.
	 */
	seq = raw_seqcount_begin(&peer_info->seqcount);
	do {
		n = peer_info->map_handles_by_node.rb_node;
		while (n) {
			handle = container_of(n, struct bus1_handle, rb_node);
			if (existing->node == handle->node) {
				if (kref_get_unless_zero(&handle->ref))
					res = handle;
				break;
			} else if (existing->node < handle->node) {
				n = n->rb_left;
			} else /* if (existing->node > handle->node) */ {
				n = n->rb_right;
			}
		}

		/*
		 * If @res is set, we have a successful lookup, as such it is
		 * always authoritative, regardless of any racing writer.
		 * However, unlike ID-lookups, if the kref-acquisition failed,
		 * we have to retry as technically the backing memory might be
		 * reused for a new handle.
		 */
	} while (!res &&
		 read_seqcount_retry(&peer_info->seqcount, seq) &&
		 ((seq = read_seqcount_begin(&peer_info->seqcount)), true));

	rcu_read_unlock();

	return res;
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
bus1_handle_unlock_peer(struct bus1_peer *peer,
			struct bus1_peer_info *peer_info)
{
	if (peer) {
		mutex_unlock(&peer_info->lock);
		bus1_peer_release(peer);
	}
	return NULL;
}

static void bus1_handle_unlink_rb(struct bus1_handle *handle,
				  struct bus1_peer_info *peer_info)
{
	lockdep_assert_held(peer_info->lock);

	/*
	 * @rb_node *and* @rb_id are unlinked, in case we were never installed.
	 * In that case, skip deletion entirely.
	 *
	 * @rb_node is unlinked in case we are part of an async RESET. In which
	 * case we're still linked in the rb-tree via @rb_id, but we're not
	 * supposed to touch the tree at all. Furthermore, we're supposed to
	 * leave the additional handle reference around, as the caller relies
	 * on it, just as it relies on the tree to stay around.
	 *
	 * If @rb_node is linked, then @rb_id is as well. In that case, remove
	 * both from their trees and rebalance.
	 */
	if (!RB_EMPTY_NODE(&handle->rb_node)) {
		write_seqcount_begin(&peer_info->seqcount);
		rb_erase(&handle->rb_id, &peer_info->map_handles_by_id);
		rb_erase(&handle->rb_node, &peer_info->map_handles_by_node);
		write_seqcount_end(&peer_info->seqcount);
		bus1_handle_unref(handle);
	}
}

static void
bus1_handle_commit_destruction(struct bus1_handle *handle,
			       struct bus1_peer_info *peer_info,
			       struct list_head *list_handles)
{
	struct bus1_handle *h;

	lockdep_assert_held(&peer_info->lock);
	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(handle->node->transaction_id != BUS1_ID_INVALID);

	/*
	 * Set the transaction_id to 0 to prevent multiple contexts destroying
	 * the handle in parallel.
	 * No need to lock seqcount since 0 is treated as BUS_ID_INVALID by all
	 * async readers.
	 */
	handle->node->transaction_id = 0;

	/*
	 * Delete owner handle from list, as we don't want it to be part of the
	 * destruction. Note that it might have already been dropped. However,
	 * the reference is never dropped by the caller, so we do this here
	 * unconditionally.
	 */
	list_del_init(&handle->link_node);
	bus1_handle_unref(handle);

	h = NULL;
	h = list_prepare_entry(h, list_handles, link_node);

	while (!list_empty(&handle->node->list_handles)) {
		list_splice_tail(&handle->node->list_handles, list_handles);
		INIT_LIST_HEAD(&handle->node->list_handles);

		mutex_unlock(&peer_info->lock);
		list_for_each_entry_continue(h, list_handles, link_node) {
			/* XXX: instantiate notification *and* queue it */
		}
		/* remember last entry to continue next round */
		h = list_prev_entry(h, link_node);
		mutex_lock(&peer_info->lock);
	}

	write_seqcount_begin(&peer_info->seqcount);
	/* XXX: allocate and set transaction ID */
	handle->node->transaction_id = 1;
	write_seqcount_end(&peer_info->seqcount);

	rcu_assign_pointer(handle->holder, NULL);
	bus1_handle_unlink_rb(handle, peer_info);
}

static void
bus1_handle_finalize_destruction(struct list_head *list_handles)
{
	struct bus1_peer_info *remote_info;
	struct bus1_handle *h;
	struct bus1_peer *remote;

	/* XXX: commit transaction */

	while ((h = list_first_entry_or_null(list_handles, struct bus1_handle,
					     link_node))) {
		list_del_init(&h->link_node);

		remote = bus1_handle_lock_holder(h, &remote_info);
		if (remote && rcu_access_pointer(h->holder)) {
			rcu_assign_pointer(h->holder, NULL);
			bus1_handle_unlink_rb(h, remote_info);
		}
		bus1_handle_unlock_peer(remote, remote_info);

		bus1_handle_unref(h);
	}
}

static void bus1_handle_release_owner(struct bus1_handle *handle,
				      struct bus1_peer_info *peer_info)
{
	LIST_HEAD(list_handles);
	bool destroyed = false;

	WARN_ON(!bus1_handle_is_owner(handle));
	WARN_ON(atomic_read(&handle->n_inflight) < 1);

	mutex_lock(&peer_info->lock);

	if (unlikely(!atomic_dec_and_test(&handle->n_inflight))) {
		mutex_unlock(&peer_info->lock);
		return;
	}

	WARN_ON(atomic_read(&handle->n_user) > 0);

	if (handle->node->transaction_id == BUS1_ID_INVALID) {
		/* just unlink, don't unref; destruction unrefs the owner */
		list_del_init(&handle->link_node);
		if (list_empty(&handle->node->list_handles)) {
			destroyed = true;
			bus1_handle_commit_destruction(handle, peer_info,
						       &list_handles);
		}
	}

	mutex_unlock(&peer_info->lock);

	if (destroyed)
		bus1_handle_finalize_destruction(&list_handles);
}

static void bus1_handle_release_holder(struct bus1_handle *handle,
				       struct bus1_peer_info *peer_info)
{
	struct bus1_peer_info *remote_info;
	struct bus1_peer *remote;
	LIST_HEAD(list_handles);
	bool dropped = false, destroyed = false;

	WARN_ON(bus1_handle_is_owner(handle));
	WARN_ON(atomic_read(&handle->n_inflight) < 1);

	mutex_lock(&peer_info->lock);
	if (unlikely(!atomic_dec_and_test(&handle->n_inflight))) {
		mutex_unlock(&peer_info->lock);
		return;
	}

	WARN_ON(atomic_read(&handle->n_user) > 0);

	if (rcu_access_pointer(handle->holder)) {
		rcu_assign_pointer(handle->holder, NULL);
		bus1_handle_unlink_rb(handle, peer_info);
		dropped = true;
	}
	mutex_unlock(&peer_info->lock);

	/* bail out, if someone else was faster */
	if (!dropped)
		return;

	remote = bus1_handle_lock_owner(handle, &remote_info);
	if (remote && handle->node->transaction_id == BUS1_ID_INVALID) {
		list_del_init(&handle->link_node);
		bus1_handle_unref(handle);
		if (list_empty(&handle->node->list_handles)) {
			destroyed = true;
			bus1_handle_commit_destruction(&handle->node->owner,
						       remote_info,
						       &list_handles);
		}
	}
	bus1_handle_unlock_peer(remote, remote_info);

	if (destroyed)
		bus1_handle_finalize_destruction(&list_handles);
}

static void bus1_handle_release_last(struct bus1_handle *handle,
				     struct bus1_peer_info *peer_info)
{
	if (bus1_handle_is_owner(handle))
		bus1_handle_release_owner(handle, peer_info);
	else
		bus1_handle_release_holder(handle, peer_info);
}

/**
 * bus1_handle_is_public() - check whether a handle is public
 * @handle:		handle to check, or NULL
 *
 * A handle is considered public as soon as it was attached to its node. It
 * will never leave that state again.
 *
 * Return: True if the node is public, false if not (or if NULL is passed).
 */
bool bus1_handle_is_public(struct bus1_handle *handle)
{
	/* private handles have: n_inflight == -1 */
	return handle && atomic_read(&handle->n_inflight) >= 0;
}

static bool bus1_handle_has_id(struct bus1_handle *handle)
{
	/* true _iff_ the handle has been installed before */
	return handle && handle->id != BUS1_ID_INVALID;
}

/**
 * bus1_handle_acquire() - try acquiring a handle
 * @handle:		handle to acquire, or NULL
 *
 * This tries to acquire a handle. Unlike object references, this function
 * acquires an actual handle reference. That is, the kind of references that
 * control whether or not the handle is owned (unlike the object references,
 * which just pin the memory and prevent it from being freed).
 *
 * Only public handles can be acquired. It is an error to call this on non
 * public handles.
 *
 * If this returns NULL, then the handle was already destroyed. The caller must
 * allocate a new one, attach it, and install it.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @handle is returned on success, NULL on failure.
 */
struct bus1_handle *bus1_handle_acquire(struct bus1_handle *handle)
{
	if (!handle || WARN_ON(!bus1_handle_is_public(handle)))
		return NULL;

	/*
	 * References to handles can only be acquired if someone else holds
	 * one. If n_inflight is 0, then we're guaranteed that the handle was
	 * either already unlinked or someone else currently holds the lock and
	 * unlinks it. Hence, the caller should forget about the handle and
	 * create a new one. At the time they link the new handle, the old one
	 * is guaranteed to be removed (since the last inflight ref is dropped
	 * with the peer lock held), except if..
	 *
	 * ..the handle is the node owner. In that case, an inflight reference
	 * can be acquired at any time. The node might be destroyed already,
	 * but that doesn't matter. The authoritative check is done at
	 * commit-time, anyway. The only guarantee we give is that this is the
	 * unique handle of that peer for the given node.
	 */
	if (!atomic_add_unless(&handle->n_inflight, 1, 0)) {
		if (!bus1_handle_is_owner(handle))
			return NULL;

		atomic_inc(&handle->n_inflight);
	}

	return handle;
}

/**
 * bus1_handle_release() - release an acquired handle
 * @handle:		handle to release, or NULL
 *
 * This releases a handle that was previously acquired via
 * bus1_handle_acquire() (or alike). Note that this might lock related peers,
 * in case the handle (or even the node) is destroyed.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_handle *bus1_handle_release(struct bus1_handle *handle)
{
	struct bus1_peer *peer;

	if (!handle || WARN_ON(!bus1_handle_is_public(handle)))
		return NULL;

	/*
	 * Release one inflight reference. If there are other references
	 * remaining, there's nothing to do for us. However, if we *might* be
	 * the last one dropping the reference, we must redirect the caller to
	 * bus1_handle_release_last(), which does a locked release.
	 *
	 * Note that if we cannot pin the holder of the handle, we know that it
	 * was already disabled. In that case, just drop the inflight counter
	 * for debug-reasons (so free() can WARN if references are remaining).
	 */

	if (atomic_add_unless(&handle->n_inflight, -1, 1))
		return NULL; /* there are other references remaining */

	/* we *may* be the last, so try again but pin and lock the holder */
	rcu_read_lock();
	peer = bus1_peer_acquire(rcu_dereference(handle->holder));
	rcu_read_unlock();
	if (peer) {
		bus1_handle_release_last(handle, bus1_peer_dereference(peer));
		bus1_peer_release(peer);
	} else {
		atomic_dec(&handle->n_inflight);
	}

	return NULL;
}

/**
 * bus1_handle_release_pinned() - release an acquired handle
 * @handle:		handle to release, or NULL
 * @peer_info:		pinned holder of @handle
 *
 * This is the same as bus1_handle_release(), but expects the caller to hold an
 * active reference to the holder of @handle, and pass in the dereferenced peer
 * info as @peer_info:
 *
 * If @handle is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_handle *bus1_handle_release_pinned(struct bus1_handle *handle,
					struct bus1_peer_info *peer_info)
{
	if (!handle || WARN_ON(!bus1_handle_is_public(handle)))
		return NULL;

	if (!atomic_add_unless(&handle->n_inflight, -1, 1))
		bus1_handle_release_last(handle, peer_info);

	return NULL;
}

/**
 * bus1_handle_attach_unlocked() - attach a handle to its node
 * @handle:		handle to attach
 * @holder:		holder of the handle
 *
 * This is the same as bus1_handle_attach(), but expects the caller to already
 * have pinned *and* locked the owning peer of the underlying node of @handle.
 *
 * Return: True if the handle was attached, false if the node is already gone.
 */
bool bus1_handle_attach_unlocked(struct bus1_handle *handle,
				 struct bus1_peer *holder)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;

	if (WARN_ON(handle->holder || bus1_handle_is_public(handle)))
		return true;

	/*
	 * During node destruction, the owner is reset to NULL once the
	 * destruction sequence has been committed. At that point, any
	 * following attach operation must fail and be treated as if the node
	 * never existed.
	 *
	 * BUT if we are the owner, the node is fully disjoint and nobody but
	 * us has access to it. Hence, an attach operation will always succeed.
	 */
	owner = rcu_access_pointer(handle->node->owner.holder);
	if (!bus1_handle_is_owner(handle) && !owner)
		return false;

	owner_info = bus1_peer_dereference(owner);
	lockdep_assert_held(&owner_info->lock);

	atomic_set(&handle->n_inflight, 1);
	rcu_assign_pointer(handle->holder, holder);
	list_add_tail(&handle->link_node, &handle->node->list_handles);
	kref_get(&handle->ref); /* node owns a reference until unlinked */

	return true;
}

/**
 * bus1_handle_attach() - attach a handle to its node
 * @handle:		handle to attach
 * @holder:		holder of the handle
 *
 * This attaches a non-public handle to its linked node. The caller must
 * provide the peer it wishes to be the holder of the new handle.
 *
 * If the underlying node is already destroyed, this will fail without touching
 * the handle or the holer.
 *
 * If this function succeeds, it will automatically acquire the handle as well.
 * See bus1_handle_acquire() for details.
 *
 * Return: True if the handle was attached, false if the node is already gone.
 */
bool bus1_handle_attach(struct bus1_handle *handle, struct bus1_peer *holder)
{
	struct bus1_peer_info *owner_info;
	struct bus1_peer *owner;
	bool res;

	if (bus1_handle_is_owner(handle)) {
		owner_info = bus1_peer_dereference(holder);
		owner = NULL;
	} else {
		rcu_read_lock();
		owner = rcu_dereference(handle->node->owner.holder);
		owner = bus1_peer_acquire(owner);
		rcu_read_unlock();

		if (!owner)
			return false;

		owner_info = bus1_peer_dereference(owner);
	}

	mutex_lock(&owner_info->lock);
	res = bus1_handle_attach_unlocked(handle, holder);
	mutex_unlock(&owner_info->lock);

	bus1_peer_release(owner);
	return res;
}

/**
 * bus1_handle_install_unlocked() - install a handle
 * @handle:		handle to install
 *
 * This installs the passed handle in its holding peer. The caller must hold
 * the peer lock of @handle->holder.
 *
 * While the attach operation links a handle to its underlying node, the
 * install operation links it into the holding peer. That is, an ID is
 * allocated and the handle is linked into the lookup trees. The caller must
 * attach a handle before it can install it.
 *
 * In case the underlying node was already destroyed, this will return NULL.
 *
 * In case another handle on the same peer raced this install, the pointer to
 * the other *acquired* and *referenced* handle is returned. The original
 * handle is left untouched. The caller should release and drop its original
 * handle and use the replacement instead.
 *
 * If the passed handle was installed successfully, a pointer to it is
 * returned.
 *
 * Return: NULL if the node is already destroyed, @handle on success, pointer
 *         to conflicting handle otherwise.
 */
struct bus1_handle *bus1_handle_install_unlocked(struct bus1_handle *handle)
{
	struct bus1_peer_info *peer_info;
	struct bus1_handle *iter, *old = NULL;
	struct rb_node *n, **slot;

	if (WARN_ON(!bus1_handle_is_public(handle)))
		return NULL;
	if (WARN_ON(handle->id != BUS1_ID_INVALID))
		return handle;

	/*
	 * If the holder is NULL, then the node was shut down in between attach
	 * and install.
	 * Return NULL to signal the caller that the node is gone. There is
	 * also no need to detach the handle. This was already done via node
	 * destruction in this case.
	 */
	if (unlikely(!rcu_access_pointer(handle->holder)))
		return NULL;

	peer_info = bus1_peer_dereference(rcu_access_pointer(handle->holder));
	lockdep_assert_held(&peer_info->lock);

	/*
	 * The holder of the handle is locked. Lock the seqcount and try
	 * inserting the new handle into the lookup trees of the peer. Note
	 * that someone might have raced us, in case the linked node is *not*
	 * exclusively owned by this handle. Hence, first try to find a
	 * conflicting handle entry. If none is found, allocate a new handle ID
	 * and insert the handle into both lookup trees. However, if a conflict
	 * is found, take a reference to it and skip the insertion. Return the
	 * conflict to the caller and let them deal with it (meaning: they
	 * unlock the peer, then destroy their temporary handle and switch over
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
			WARN_ON(iter->id == BUS1_ID_INVALID);

			old = handle;
			handle = bus1_handle_ref(iter);
			WARN_ON(!bus1_handle_acquire(handle));
			break;
		} else if (handle->node < iter->node) {
			slot = &n->rb_left;
		} else /* if (handle->node > iter->node) */ {
			slot = &n->rb_right;
		}
	}
	if (likely(!old)) {
		handle->id = ++peer_info->handle_ids;

		/* insert into node-map */
		rb_link_node_rcu(&handle->rb_node, n, slot);
		rb_insert_color(&handle->rb_node,
				&peer_info->map_handles_by_node);

		/* insert into id-map */
		n = rb_last(&peer_info->map_handles_by_id);
		if (n)
			rb_link_node_rcu(&handle->rb_id, n, &n->rb_right);
		else
			rb_link_node_rcu(&handle->rb_id, NULL,
					 &peer_info->map_handles_by_id.rb_node);
		rb_insert_color(&handle->rb_id, &peer_info->map_handles_by_id);
	}
	write_seqcount_end(&peer_info->seqcount);

	return handle;
}

/**
 * bus1_handle_commit() - commit an acquired handle
 * @handle:		handle to commit
 * @msg_seq:		sequence number of the committing transaction
 *
 * This acquires a *real* user visible reference to the passed handle, as part
 * of a transaction. The caller must provide the final transaction sequence
 * number as @msg_seq. It is used to order against node destruction.
 *
 * In case the handle references was committed successfully, the handle ID is
 * returned. If the handle was already destroyed, BUS1_ID_INVALID is returned.
 *
 * Return: The handle ID to store in the message is returned.
 */
u64 bus1_handle_commit(struct bus1_handle *handle, u64 msg_seq)
{
	struct bus1_peer_info *peer_info;
	struct bus1_peer *peer;
	unsigned int seq;
	u64 node_seq, v;

	rcu_read_lock();
	peer = rcu_dereference(handle->node->owner.holder);
	if (!peer || !(peer_info = rcu_dereference(peer->info))) {
		/*
		 * Owner handles are reset *after* the transaction id has been
		 * stored synchronously, and peer-info even after that. Hence,
		 * we can safely read the transaction ID and all barriers are
		 * provided by rcu.
		 */
		node_seq = handle->node->transaction_id;
	} else {
		/*
		 * Try reading the transaction id. We must synchronize via the
		 * seqcount to guarantee stability across an invalidation
		 * transaction.
		 */
		do {
			seq = read_seqcount_begin(&peer_info->seqcount);
			node_seq = handle->node->transaction_id;
		} while (read_seqcount_retry(&peer_info->seqcount, seq));
	}
	rcu_read_unlock();

	if (node_seq == 0 || msg_seq < node_seq) {
		if (atomic_inc_return(&handle->n_user) == 1)
			WARN_ON(atomic_inc_return(&handle->n_inflight) < 2);
		v = handle->id;
	} else {
		v = BUS1_ID_INVALID;
	}

	return v;
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
	if (n_user < 0) {
		/* DEC did *NOT* happen, peer does not own a reference */
		r = -ESTALE;
	} else if (n_user > 0) {
		/* DEC happened, but it wasn't the last; bail out */
		r = 0;
	} else {
		/* DEC happened and dropped to 0, release the linked ref */
		bus1_handle_release_pinned(handle, peer_info);
		r = 0;
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
	LIST_HEAD(list_handles);
	int r;

	handle = bus1_handle_find_by_id(peer_info, id);
	if (!handle)
		return -ENXIO;

	mutex_lock(&peer_info->lock);
	if (!bus1_handle_is_owner(handle)) {
		r = -EPERM;
	} else if (handle->node->transaction_id != BUS1_ID_INVALID) {
		r = -EINPROGRESS;
	} else {
		bus1_handle_commit_destruction(handle, peer_info,
					       &list_handles);
		r = 0;
	}
	mutex_unlock(&peer_info->lock);

	if (r < 0)
		goto exit;

	bus1_handle_finalize_destruction(&list_handles);
	r = 0;

exit:
	bus1_handle_unref(handle);
	return r;
}

/**
 * bus1_handle_flush_all() - flush all owned handles
 * @peer_info:		peer to operate on
 * @map:		rb-tree to push handles into
 *
 * This removes all owned handles from the given peer and stores them for later
 * removal into @map. See bus1_handle_finish_all() for the tail call.
 *
 * The caller must hold the peer lock of @peer_info.
 */
void bus1_handle_flush_all(struct bus1_peer_info *peer_info,
			   struct rb_root *map)
{
	struct bus1_handle *handle, *t;

	/*
	 * Get a copy of the id-map root and reset it to NULL. This is
	 * basically equivalent to calling rb_erase() on all our handles.
	 * However, we now have the benefit that the tree is still intact and
	 * we can traverse it safely. We just must make sure not to screw with
	 * the rb_id/rb_node pointers, as concurrent lookups might race us. The
	 * rb-removal helpers check for RB_EMPTY_NODE(&h->rb_node), if true
	 * they assume the entry is removed by the caller (which in our case is
	 * us in bus1_handle_finish_all()). Note that RB_CLEAR_NODE only
	 * touches the parent pointer, so racing lookups will not be affected.
	 *
	 * Unlike normal handle destruction/release, we unlink the handle
	 * *before* performing the operation. It might not be obvious why this
	 * is safe, but the only two possible races are:
	 *
	 *   1) A local SEND/RELEASE/DESTROY ioctl that adds or removes
	 *      handles. Those are by definition undefined if run in parallel
	 *      to RESET. As such, it doesn't matter whether they operate on
	 *      the new or old tree.
	 *
	 *   2) A remote peer sends us a handle. If it happens on the old tree,
	 *      it will be cleaned up together with any previous handle. If it
	 *      happens on the new tree, it will create a possible duplicate
	 *      handle on the new tree and be treated as if it was another
	 *      peer. As such, it is fully involved in the transaction logic.
	 *
	 * Hence, a clean disconnect of the whole tree and later finalizing it
	 * async/unlocked will have the same effect as an atomic destruction of
	 * all owned nodes, followed by a non-atomic release of all handles.
	 */

	lockdep_assert_held(&peer_info->lock);

	write_seqcount_begin(&peer_info->seqcount);
	*map = peer_info->map_handles_by_id;
	WRITE_ONCE(peer_info->map_handles_by_id.rb_node, NULL);
	WRITE_ONCE(peer_info->map_handles_by_node.rb_node, NULL);
	write_seqcount_end(&peer_info->seqcount);

	rbtree_postorder_for_each_entry_safe(handle, t, map, rb_id)
		RB_CLEAR_NODE(&handle->rb_node);
}

/**
 * bus1_handle_finish_all() - finish set of handles
 * @peer_info:		peer to operate on
 * @map:		map of handles
 *
 * This is the tail call of bus1_handle_flush_all(). It destroys all owned
 * nodes of a peer, and releases all owned handles.
 *
 * This must be called *without* the peer lock held.
 */
void bus1_handle_finish_all(struct bus1_peer_info *peer_info,
			    struct rb_root *map)
{
	struct bus1_handle *handle, *t;
	LIST_HEAD(list_handles);

	/*
	 * See bus1_handle_flush_all() why it is safe to do this on a
	 * disconnected tree.
	 *
	 * Note that we might have racing RELEASE or DESTROY calls on handles
	 * linked to this tree. This is completely fine. They will work just
	 * like normal, but skip the rb-tree cleanup. However, we must make
	 * sure to only cleanup stuff here that is *not* racing us.
	 */

	rbtree_postorder_for_each_entry_safe(handle, t, map, rb_id) {
		if (bus1_handle_is_owner(handle)) {
			INIT_LIST_HEAD(&list_handles);
			mutex_lock(&peer_info->lock);
			if (handle->node->transaction_id == BUS1_ID_INVALID)
				bus1_handle_commit_destruction(handle,
							       peer_info,
							       &list_handles);
			mutex_unlock(&peer_info->lock);
		} else {
			if (atomic_xchg(&handle->n_user, 0) > 0)
				bus1_handle_release_pinned(handle, peer_info);
		}

		/* our stolen reference from bus1_handle_unlink_rb() */
		bus1_handle_unref(handle);
	}

	bus1_handle_finalize_destruction(&list_handles);
}

#define BUS1_HANDLE_BATCH_FIRST(_batch, _pos)			\
	((_pos) = 0, (_batch)->entries)

#define BUS1_HANDLE_BATCH_NEXT(_iter, _pos)			\
	((!(++(_pos) % BUS1_HANDLE_BATCH_SIZE)) ?		\
			((_iter) + 1)->next :			\
			((_iter) + 1))

#define BUS1_HANDLE_BATCH_FOREACH_ALLOCATED(_iter, _pos, _batch)	\
	for ((_iter) = BUS1_HANDLE_BATCH_FIRST((_batch), (_pos));	\
	     (_pos) < (_batch)->n_allocated;				\
	     (_iter) = BUS1_HANDLE_BATCH_NEXT((_iter), (_pos)))

#define BUS1_HANDLE_BATCH_FOREACH_HANDLE(_iter, _pos, _batch)		\
	for ((_iter) = BUS1_HANDLE_BATCH_FIRST((_batch), (_pos));	\
	     (_pos) < (_batch)->n_handles;				\
	     (_iter) = BUS1_HANDLE_BATCH_NEXT((_iter), (_pos)))

static void bus1_handle_batch_init(struct bus1_handle_batch *batch,
				   size_t n_entries)
{
	batch->n_handles = 0;
	if (n_entries < BUS1_HANDLE_BATCH_SIZE) {
		batch->n_allocated = n_entries;
	} else {
		batch->n_allocated = BUS1_HANDLE_BATCH_SIZE;
		batch->entries[BUS1_HANDLE_BATCH_SIZE].next = NULL;
	}
}

static int bus1_handle_batch_create(struct bus1_handle_batch *batch,
				    size_t n_entries)
{
	union bus1_handle_entry *slot, *e;

	if (n_entries == batch->n_allocated)
		return 0;

	/* the set must be unused and newly initialized */
	if (WARN_ON(n_entries < batch->n_allocated ||
		    batch->n_handles > 0 ||
		    batch->n_allocated != BUS1_HANDLE_BATCH_SIZE ||
		    batch->entries[BUS1_HANDLE_BATCH_SIZE].next))
		return -EINVAL;

	/* skip already allocated entries */
	n_entries -= BUS1_HANDLE_BATCH_SIZE;
	slot = &batch->entries[BUS1_HANDLE_BATCH_SIZE];

	while (n_entries > 0) {
		if (n_entries < BUS1_HANDLE_BATCH_SIZE) {
			e = kmalloc(sizeof(*e) * n_entries, GFP_KERNEL);
			if (!e)
				return -ENOMEM;

			slot->next = e;
			batch->n_allocated += n_entries;
			break;
		}

		e = kmalloc(sizeof(*e) * (BUS1_HANDLE_BATCH_SIZE + 1),
			    GFP_KERNEL);
		if (!e)
			return -ENOMEM;

		slot->next = e;
		slot = &e[BUS1_HANDLE_BATCH_SIZE];
		slot->next = NULL;

		batch->n_allocated += BUS1_HANDLE_BATCH_SIZE;
		n_entries -= BUS1_HANDLE_BATCH_SIZE;
	}

	return 0;
}

static void bus1_handle_batch_destroy(struct bus1_handle_batch *batch)
{
	union bus1_handle_entry *t, *entry;
	size_t pos;

	if (!batch || !batch->n_allocated)
		return;

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(entry, pos, batch) {
		if (!entry->handle)
			continue;
		if (bus1_handle_is_public(entry->handle))
			bus1_handle_release(entry->handle);
		bus1_handle_unref(entry->handle);
	}

	if (batch->n_allocated > BUS1_HANDLE_BATCH_SIZE) {
		batch->n_allocated -= BUS1_HANDLE_BATCH_SIZE;
		entry = batch->entries[BUS1_HANDLE_BATCH_SIZE].next;
		while (batch->n_allocated > BUS1_HANDLE_BATCH_SIZE) {
			t = entry;
			entry = entry[BUS1_HANDLE_BATCH_SIZE].next;
			batch->n_allocated -= BUS1_HANDLE_BATCH_SIZE;
			kfree(t);
		}
		kfree(entry);
	}

	batch->n_allocated = 0;
	batch->n_handles = 0;
}

static int bus1_handle_batch_import(struct bus1_handle_batch *batch,
				    const u64 __user *ids,
				    size_t n_ids)
{
	union bus1_handle_entry *block;

	if (WARN_ON(n_ids != batch->n_allocated || batch->n_handles > 0))
		return -EINVAL;

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

void bus1_handle_transfer_init(struct bus1_handle_transfer *transfer,
			       struct bus1_peer *peer,
			       size_t n_entries)
{
	transfer->peer = peer;
	transfer->n_new = 0;
	bus1_handle_batch_init(&transfer->batch, n_entries);
}

void bus1_handle_transfer_destroy(struct bus1_handle_transfer *transfer)
{
	if (!transfer)
		return;

	/* safe to be called multiple times */
	bus1_handle_batch_destroy(&transfer->batch);
}

int bus1_handle_transfer_instantiate(struct bus1_handle_transfer *transfer,
				     const u64 __user *ids,
				     size_t n_ids)
{
	struct bus1_peer_info *peer_info;
	union bus1_handle_entry *entry;
	struct bus1_handle *handle;
	size_t pos;
	int r;

	r = bus1_handle_batch_create(&transfer->batch, n_ids);
	if (r < 0)
		return r;

	r = bus1_handle_batch_import(&transfer->batch, ids, n_ids);
	if (r < 0)
		return r;

	peer_info = bus1_peer_dereference(transfer->peer);

	BUS1_HANDLE_BATCH_FOREACH_ALLOCATED(entry, pos, &transfer->batch) {
		if (entry->id == BUS1_ID_INVALID) {
			handle = bus1_handle_new();
			if (IS_ERR(handle))
				return PTR_ERR(handle);
			++transfer->n_new;
		} else {
			/*
			 * If you transfer non-existant, or destructed handles,
			 * we simply store NULL in the batch. We might
			 * optionally allow returning an error instead. But
			 * given the async nature of handle destruction, it
			 * seems rather unlikely that callers want to handle
			 * that.
			 */
			handle = bus1_handle_find_by_id(peer_info, entry->id);
			if (handle && !bus1_handle_acquire(handle))
				handle = bus1_handle_unref(handle);
		}

		entry->handle = handle;
		++transfer->batch.n_handles;
	}

	return 0;
}

void bus1_handle_inflight_init(struct bus1_handle_inflight *inflight,
			       size_t n_entries)
{
	inflight->n_new = 0;
	inflight->n_new_local = 0;
	bus1_handle_batch_init(&inflight->batch, n_entries);
}

void bus1_handle_inflight_destroy(struct bus1_handle_inflight *inflight)
{
	if (!inflight)
		return;

	/* safe to be called multiple times */
	bus1_handle_batch_destroy(&inflight->batch);
}

int bus1_handle_inflight_instantiate(struct bus1_handle_inflight *inflight,
				     struct bus1_peer_info *peer_info,
				     struct bus1_handle_transfer *transfer)
{
	union bus1_handle_entry *from, *to;
	struct bus1_handle *handle;
	size_t pos_from, pos_to;
	int r;

	r = bus1_handle_batch_create(&inflight->batch,
				     transfer->batch.n_handles);
	if (r < 0)
		return r;

	to = BUS1_HANDLE_BATCH_FIRST(&inflight->batch, pos_to);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(from, pos_from, &transfer->batch) {
		WARN_ON(pos_to >= inflight->batch.n_allocated);

		if (!from->handle) {
			handle = NULL;
		} else {
			handle = bus1_handle_find_by_node(peer_info,
							  from->handle);
			if (handle && !bus1_handle_acquire(handle))
				handle = bus1_handle_unref(handle);
			if (!handle) {
				handle = bus1_handle_new_copy(from->handle);
				if (IS_ERR(handle))
					return PTR_ERR(handle);
			}
		}

		to->handle = handle;
		to = BUS1_HANDLE_BATCH_NEXT(to, pos_to);
		++inflight->batch.n_handles;
	}

	return 0;
}

void bus1_handle_inflight_install(struct bus1_handle_inflight *inflight,
				  struct bus1_peer *peer,
				  struct bus1_handle_transfer *transfer)
{
	struct bus1_peer_info *src_info, *dst_info;
	struct bus1_peer *src, *dst;
	struct bus1_handle *h, *t;
	union bus1_handle_entry *e;
	size_t pos, n_installs;

	if (inflight->batch.n_handles < 1)
		return;

	src = transfer->peer;
	dst = peer;
	src_info = bus1_peer_dereference(src);
	dst_info = bus1_peer_dereference(dst);
	n_installs = inflight->n_new;

	if (transfer->n_new > 0 || inflight->n_new_local > 0) {
		mutex_lock(&src_info->lock);

		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &transfer->batch) {
			if (transfer->n_new < 1)
				break;

			h = e->handle;
			if (!h || bus1_handle_is_public(h))
				continue;

			--transfer->n_new;
			WARN_ON(!bus1_handle_attach_unlocked(h, src));
			WARN_ON(bus1_handle_install_unlocked(h) != h);
		}
		WARN_ON(transfer->n_new > 0);

		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			if (inflight->n_new_local < 1)
				break;

			h = e->handle;
			if (!h || bus1_handle_is_public(h))
				continue;

			--inflight->n_new;
			--inflight->n_new_local;

			if (!bus1_handle_attach_unlocked(h, dst))
				e->handle = bus1_handle_unref(h);
		}
		WARN_ON(inflight->n_new_local > 0);

		mutex_unlock(&src_info->lock);
	}

	if (inflight->n_new > 0) {
		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			if (inflight->n_new < 1)
				break;

			h = e->handle;
			if (!h || bus1_handle_is_public(h))
				continue;

			--inflight->n_new;

			if (!bus1_handle_attach(h, dst))
				e->handle = bus1_handle_unref(h);
		}
		WARN_ON(inflight->n_new > 0);
	}

	if (n_installs > 0) {
		mutex_lock(&dst_info->lock);
		BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
			if (n_installs < 1)
				break;

			h = e->handle;
			if (!h || bus1_handle_has_id(h))
				continue;

			--n_installs;

			t = bus1_handle_install_unlocked(h);
			if (!t) {
				e->handle = bus1_handle_unref(h);
			} else if (t != h) {
				/* conflict: detach @h, switch to @t */
				mutex_unlock(&dst_info->lock);
				bus1_handle_release(h);
				bus1_handle_unref(h);
				e->handle = t;
				mutex_lock(&dst_info->lock);
			}
		}
		mutex_unlock(&dst_info->lock);
		WARN_ON(n_installs > 0);
	}
}

void bus1_handle_inflight_commit(struct bus1_handle_inflight *inflight,
				 u64 seq)
{
	union bus1_handle_entry *e;
	struct bus1_handle *h;
	size_t pos;

	WARN_ON(inflight->batch.n_handles != inflight->batch.n_allocated);

	BUS1_HANDLE_BATCH_FOREACH_HANDLE(e, pos, &inflight->batch) {
		h = e->handle;
		if (h) {
			e->id = bus1_handle_commit(h, seq);
			bus1_handle_unref(h);
		} else {
			e->id = BUS1_ID_INVALID;
		}
	}

	inflight->batch.n_handles = 0;
}
