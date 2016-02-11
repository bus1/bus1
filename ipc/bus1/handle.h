#ifndef __BUS1_HANDLE_H
#define __BUS1_HANDLE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Handles
 *
 * The object system on a bus is based on nodes and handles. Any peer can
 * allocate new, local objects at any time. They automatically become the sole
 * owner of the object. Those objects can be passed as payload of messages. The
 * recipient will thus gain a reference to the object as well. Additionally, an
 * object can be the destination of a message, in which case the message is
 * always sent to the original creator (and thus the owner) of the object.
 *
 * Internally, objects are called 'nodes'. A reference to an object is a
 * 'handle'. Whenever a new node is created, the owner implicitly gains an
 * handle as well. In fact, handles are the only way to refer to a node. The
 * node itself is entirely hidden in the implementation.
 *
 * Whenever a handle is passed as payload of a message, the target peer will
 * gain a handle linked to the same underlying node. This works regardless
 * whether the sender is the owner of the underlying node, or not.
 *
 * Each peer can identify all its handles (both owned and un-owned) by a 64bit
 * integer. The namespace is local to each peer, and the numbers cannot be
 * compared with the numbers of other peers (in fact, they will be very likely
 * to clash, but might still have *different* underlying nodes). However, if a
 * peer receives a reference to the same node multiple times, the resulting
 * handle will be the same. The kernel keeps count how often each peer owns a
 * handle.
 *
 * If a peer no longer requires a specific handle, it must release it. If the
 * peer releases its last reference to a handle, the handle will be destroyed.
 *
 * The ID of an handle is (almost) never reused. That is, once a handle was
 * fully released, any new handle the peer receives will have a different ID.
 * The only scenario where an ID is reused, is if the peer gains a new handle
 * to an underlying node that it already owned a handle for earlier. This might
 * happen, for instance, if a message is inflight that carries a handle that
 * the peer was just about to release. Furthermore, the handle of the owner of
 * a node is internally pinned. As such, it is always reused if the owner gains
 * a handle to its own node again (this is required for explicit node
 * destruction).
 * Note that such ID-reuse is not guaranteed, though. If a peer used to own a
 * handle, dropped it and gains another one for the same underlying node, the
 * new ID might be completely different! The only guarantee here is: If the ID
 * is the same as a previously owned ID, then the underlying node is still the
 * same.
 *
 * Once all handles to a specific node have been released, the node is
 * unreferenced and is automatically destroyed. The owner of the node is
 * notified of this, so it can destroy any linked state. Note that the owner of
 * a node owns a handle themself, so it needs to release it as well to trigger
 * the destruction of the node.
 * Additionally, the owner of a node (and *only* the owner) can trigger
 * destruction of a node manually (even if other peers still own handles). In
 * this case, all peers that own a handle are notified by this.
 *
 * Node destruction is fully synchronized with any transaction. That is, a node
 * and all its handles are valid in every message that is transmitted *before*
 * the notification of its destruction. Furthermore, no message after this
 * notification will carry the ID of such a destructed node.
 * Note that message transactions are fully async. That is, there is no unique
 * point in time that a message is synchronized with another message. Hence,
 * whether a specific handle passed with a message is still valid or not,
 * cannot be predicted by the sender, but only by one of the receivers.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>

struct bus1_handle;
struct bus1_peer;
struct bus1_peer_info;

struct bus1_handle *bus1_handle_new_copy(struct bus1_handle *existing);
struct bus1_handle *bus1_handle_new(void);
struct bus1_handle *bus1_handle_ref(struct bus1_handle *handle);
struct bus1_handle *bus1_handle_unref(struct bus1_handle *handle);
struct bus1_handle *bus1_handle_find_by_id(struct bus1_peer_info *peer_info,
					   u64 id);
struct bus1_handle *bus1_handle_find_by_node(struct bus1_peer_info *peer_info,
					     struct bus1_handle *existing);

bool bus1_handle_is_public(struct bus1_handle *handle);
struct bus1_handle *bus1_handle_acquire(struct bus1_handle *handle);
struct bus1_handle *bus1_handle_release(struct bus1_handle *handle);
struct bus1_handle *bus1_handle_release_pinned(struct bus1_handle *handle,
					struct bus1_peer_info *peer_info);

bool bus1_handle_attach(struct bus1_handle *handle, struct bus1_peer *holder);
bool bus1_handle_attach_unlocked(struct bus1_handle *handle,
				 struct bus1_peer *holder);
struct bus1_handle *bus1_handle_install_unlocked(struct bus1_handle *handle);
u64 bus1_handle_commit(struct bus1_handle *handle, u64 msg_seq);

int bus1_handle_release_by_id(struct bus1_peer_info *peer_info, u64 id);
int bus1_handle_destroy_by_id(struct bus1_peer_info *peer_info, u64 id);
void bus1_handle_flush_all(struct bus1_peer_info *peer_info,
			   struct rb_root *map);
void bus1_handle_finish_all(struct bus1_peer_info *peer_info,
			    struct rb_root *map);

#endif /* __BUS1_HANDLE_H */
