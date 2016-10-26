#ifndef __BUS1_HANDLE_H
#define __BUS1_HANDLE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Handles
 *
 * The object system on a bus is based on 'nodes' and 'handles'. Any peer can
 * allocate new, local objects at any time. The creator automatically becomes
 * the sole owner of the object. References to objects can be passed as payload
 * of messages. The recipient will then gain their own reference to the object
 * as well. Additionally, an object can be the destination of a message, in
 * which case the message is always sent to the original creator (and thus the
 * owner) of the object.
 *
 * Internally, objects are called 'nodes'. A reference to an object is a
 * 'handle'. Whenever a new node is created, the owner implicitly gains an
 * handle as well. In fact, handles are the only way to refer to a node. The
 * node itself is entirely hidden in the implementation, and visible in the API
 * as an "anchor handle".
 *
 * Whenever a handle is passed as payload of a message, the target peer will
 * gain a handle linked to the same underlying node. This works regardless
 * of whether the sender is the owner of the underlying node, or not.
 *
 * Each peer can identify all its handles (both owned and un-owned) by a 64-bit
 * integer. The namespace is local to each peer, and the numbers cannot be
 * compared with the numbers of other peers (in fact, they are very likely
 * to clash, but might still have *different* underlying nodes). However, if a
 * peer receives a reference to the same node multiple times, the resulting
 * handle will be the same. The kernel keeps count of how often each peer owns
 * a handle.
 *
 * If a peer no longer requires a specific handle, it can release it. If the
 * peer releases its last reference to a handle, the handle will be destroyed.
 *
 * The owner of a node (and *only* the owner) can trigger the destruction of a
 * node (even if other peers still own handles to it). In this case, all peers
 * that own a handle are notified of this fact.
 * Once all handles to a specific node have been released (except for the handle
 * internally pinned in the node itself), the owner of the node is notified of
 * this, so it can potentially destroy both any linked state and the node
 * itself.
 *
 * Node destruction is fully synchronized with any transaction. That is, a node
 * and all its handles are valid in every message that is transmitted *before*
 * the notification of its destruction. Furthermore, no message after this
 * notification will carry the ID of such a destroyed node.
 * Note that message transactions are asynchronous. That is, there is no unique
 * point in time that a message is synchronized with another message. Hence,
 * whether a specific handle passed with a message is still valid or not,
 * cannot be predicted by the sender, but only by one of the receivers.
 */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rbtree.h>
#include "util.h"
#include "util/queue.h"

struct bus1_peer;
struct bus1_tx;

/**
 * enum bus1_handle_bits - node flags
 * @BUS1_HANDLE_BIT_RELEASED:		The anchor handle has been released.
 *					Any further attach operation will still
 *					work, but result in a stale attach,
 *					even in case of re-attach of the anchor
 *					itself.
 * @BUS1_HANDLE_BIT_DESTROYED:		A destruction has already been
 *					scheduled for this node.
 */
enum bus1_handle_bits {
	BUS1_HANDLE_BIT_RELEASED,
	BUS1_HANDLE_BIT_DESTROYED,
};

/**
 * struct bus1_handle - object handle
 * @ref:				object reference counter
 * @n_weak:				number of weak references
 * @n_user:				number of user references
 * @holder:				holder of this handle
 * @anchor:				anchor handle
 * @tlink:				singly-linked list for free use
 * @rb_to_peer:				rb-link into peer by ID
 * @id:					current ID
 * @qnode:				queue node for notifications
 * @node.map_handles:			map of attached handles by peer
 * @node.flags:				node flags
 * @node.n_strong:			number of strong references
 * @remote.rb_to_anchor:		rb-link into node by peer
 */
struct bus1_handle {
	struct kref ref;
	atomic_t n_weak;
	atomic_t n_user;
	struct bus1_peer *holder;
	struct bus1_handle *anchor;
	struct bus1_handle *tlink;
	struct rb_node rb_to_peer;
	u64 id;
	struct bus1_queue_node qnode;
	union {
		struct {
			struct rb_root map_handles;
			unsigned long flags;
			atomic_t n_strong;
		} node;
		struct {
			struct rb_node rb_to_anchor;
		} remote;
	};
};

struct bus1_handle *bus1_handle_new_anchor(struct bus1_peer *holder);
struct bus1_handle *bus1_handle_new_remote(struct bus1_peer *holder,
					   struct bus1_handle *other);
void bus1_handle_free(struct kref *ref);
struct bus1_peer *bus1_handle_acquire_owner(struct bus1_handle *handle);

struct bus1_handle *bus1_handle_ref_by_other(struct bus1_peer *peer,
					     struct bus1_handle *handle);

struct bus1_handle *bus1_handle_acquire_slow(struct bus1_handle *handle,
					     bool strong);
struct bus1_handle *bus1_handle_acquire_locked(struct bus1_handle *handle,
					       bool strong);
void bus1_handle_release_slow(struct bus1_handle *h, bool strong);

void bus1_handle_destroy_locked(struct bus1_handle *h, struct bus1_tx *tx);
bool bus1_handle_is_live_at(struct bus1_handle *h, u64 timestamp);

struct bus1_handle *bus1_handle_import(struct bus1_peer *peer,
				       u64 id,
				       bool *is_newp);
u64 bus1_handle_identify(struct bus1_handle *h);
void bus1_handle_export(struct bus1_handle *h);
void bus1_handle_forget(struct bus1_handle *h);
void bus1_handle_forget_keep(struct bus1_handle *h);

/**
 * bus1_handle_is_anchor() - check whether handle is an anchor
 * @h:			handle to check
 *
 * This checks whether @h is an anchor. That is, @h was created via
 * bus1_handle_new_anchor(), rather than via bus1_handle_new_remote().
 *
 * Return: True if it is an anchor, false if not.
 */
static inline bool bus1_handle_is_anchor(struct bus1_handle *h)
{
	return h == h->anchor;
}

/**
 * bus1_handle_is_live() - check whether handle is live
 * @h:			handle to check
 *
 * This checks whether the given handle is still live. That is, its anchor was
 * not destroyed, yet.
 *
 * Return: True if it is live, false if already destroyed.
 */
static inline bool bus1_handle_is_live(struct bus1_handle *h)
{
	return !test_bit(BUS1_HANDLE_BIT_DESTROYED, &h->anchor->node.flags);
}

/**
 * bus1_handle_is_public() - check whether handle is public
 * @h:			handle to check
 *
 * This checks whether the given handle is public. That is, it was exported to
 * user-space and at least one public reference is left.
 *
 * Return: True if it is public, false if not.
 */
static inline bool bus1_handle_is_public(struct bus1_handle *h)
{
	return atomic_read(&h->n_user) > 0;
}

/**
 * bus1_handle_ref() - acquire object reference
 * @h:			handle to operate on, or NULL
 *
 * This acquires an object reference to @h. The caller must already hold a
 * reference. Otherwise, the behavior is undefined.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @h is returned.
 */
static inline struct bus1_handle *bus1_handle_ref(struct bus1_handle *h)
{
	if (h)
		kref_get(&h->ref);
	return h;
}

/**
 * bus1_handle_unref() - release object reference
 * @h:			handle to operate on, or NULL
 *
 * This releases an object reference. If the reference count drops to 0, the
 * object is released (rcu-delayed).
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_handle *bus1_handle_unref(struct bus1_handle *h)
{
	if (h)
		kref_put(&h->ref, bus1_handle_free);
	return NULL;
}

/**
 * bus1_handle_acquire() - acquire weak/strong reference
 * @h:			handle to operate on, or NULL
 * @strong:		whether to acquire a strong reference
 *
 * This acquires a weak/strong reference to the node @h is attached to.
 * This always succeeds. However, if a conflict is detected, @h is
 * unreferenced and the conflicting handle is returned (with an object
 * reference taken and strong reference acquired).
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: Pointer to the acquired handle is returned.
 */
static inline struct bus1_handle *
bus1_handle_acquire(struct bus1_handle *h,
		    bool strong)
{
	if (h) {
		if (bus1_atomic_add_if_ge(&h->n_weak, 1, 1) < 1) {
			h = bus1_handle_acquire_slow(h, strong);
		} else if (bus1_atomic_add_if_ge(&h->anchor->node.n_strong,
						 1, 1) < 1) {
			WARN_ON(h != bus1_handle_acquire_slow(h, strong));
			WARN_ON(atomic_dec_return(&h->n_weak) < 1);
		}
	}
	return h;
}

/**
 * bus1_handle_release() - release weak/strong reference
 * @h:			handle to operate on, or NULL
 * @strong:		whether to release a strong reference
 *
 * This releases a weak or strong reference to the node @h is attached to.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_handle *
bus1_handle_release(struct bus1_handle *h, bool strong)
{
	if (h) {
		if (strong &&
		    bus1_atomic_add_if_ge(&h->anchor->node.n_strong, -1, 2) < 2)
			bus1_handle_release_slow(h, true);
		else if (bus1_atomic_add_if_ge(&h->n_weak, -1, 2) < 2)
			bus1_handle_release_slow(h, false);
	}
	return NULL;
}

/**
 * bus1_handle_release_n() - release multiple references
 * @h:			handle to operate on, or NULL
 * @n:			number of references to release
 * @strong:		whether to release strong references
 *
 * This releases @n weak or strong references to the node @h is attached to.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_handle *
bus1_handle_release_n(struct bus1_handle *h, unsigned int n, bool strong)
{
	if (h && n > 0) {
		if (n > 1) {
			if (strong)
				WARN_ON(atomic_sub_return(n - 1,
						&h->anchor->node.n_strong) < 1);
			WARN_ON(atomic_sub_return(n - 1, &h->n_weak) < 1);
		}
		bus1_handle_release(h, strong);
	}
	return NULL;
}

#endif /* __BUS1_HANDLE_H */
