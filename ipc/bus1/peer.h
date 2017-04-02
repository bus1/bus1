#ifndef __BUS1_PEER_H
#define __BUS1_PEER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Peers
 *
 * A peer context provides access to the bus1 system. A peer itself is not a
 * routable entity, but rather only a local anchor to serve as gateway to the
 * bus. To participate on the bus, you need to allocate a peer. This peer
 * manages all your state on the bus, including all allocated nodes, owned
 * handles, incoming messages, and more.
 *
 * A peer is split into 3 sections:
 *   - A static section that is initialized at peer creation and never changes
 *   - A peer-local section that is only ever accessed by ioctls done by the
 *     peer itself.
 *   - A data section that might be accessed by remote peers when interacting
 *     with this peer.
 *
 * All peers on the system operate on the same level. There is no context a
 * peer is linked into. Hence, you can never lock multiple peers at the same
 * time. Instead, peers provide active-references. Before performing an
 * operation on a peer, an active reference must be acquired, and held as long
 * as the operation goes on. When done, the reference is released again.
 * When a peer is disconnected, no more active references can be acquired, and
 * any outstanding operation is waited for before the peer is destroyed.
 *
 * Additionally to active-references, there are 2 locks: A peer-local lock and
 * a data lock. The peer-local lock is used to synchronize operations done by
 * the peer itself. It is never acquired by a remote peer. The data lock
 * protects the data of the peer, which might be modified by remote peers. The
 * data lock nests underneath the local-lock. Furthermore, the data-lock
 * critical sections must be kept small and never block indefinitely. Remote
 * peers might wait for data-locks, hence they must rely on not being DoSed.
 * The local peer lock, however, is private to the peer itself and no such
 * restrictions apply. It is mostly used to give the impression of atomic
 * operations (i.e., making the API appear consistent and coherent).
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "user.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

struct bus1_message;
struct cred;
struct dentry;

/**
 * struct bus1_peer - peer context
 * @id:				peer ID
 * @flags:			peer flags
 * @user:			pinned user
 * @rcu:			rcu-delayed kfree of peer
 * @waitq:			peer wide wait queue
 * @active:			active references
 * @debugdir:			debugfs root of this peer, or NULL/ERR_PTR
 * @data.lock:			data lock
 * @data.pool:			data pool
 * @data.queue:			message queue
 * @data.limits:		resource limit counter
 * @local.lock:			local peer runtime lock
 * @local.seed:			pinned seed message
 * @local.map_handles:		map of owned handles (by handle ID)
 * @local.handle_ids:		handle ID allocator
 */
struct bus1_peer {
	u64 id;
	u64 flags;
	struct bus1_user *user;
	struct rcu_head rcu;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct dentry *debugdir;

	struct {
		struct mutex lock;
		struct bus1_pool pool;
		struct bus1_queue queue;
		struct bus1_user_limits limits;
	} data;

	struct {
		struct mutex lock;
		struct bus1_message *seed;
		struct rb_root map_handles;
		u64 handle_ids;
	} local;
};

struct bus1_peer *bus1_peer_new(const struct cred *cred);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);
long bus1_peer_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/**
 * bus1_peer_acquire() - acquire active reference to peer
 * @peer:	peer to operate on, or NULL
 *
 * Acquire a new active reference to the given peer. If the peer was not
 * activated yet, or if it was already deactivated, this will fail.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: Pointer to peer, NULL on failure.
 */
static inline struct bus1_peer *bus1_peer_acquire(struct bus1_peer *peer)
{
	if (peer && bus1_active_acquire(&peer->active))
		return peer;
	return NULL;
}

/**
 * bus1_peer_release() - release an active reference
 * @peer:	handle to release, or NULL
 *
 * This releases an active reference to a peer, acquired previously via
 * bus1_peer_acquire().
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_peer *bus1_peer_release(struct bus1_peer *peer)
{
	if (peer) {
		/*
		 * An active reference is sufficient to keep a peer alive. As
		 * such, releasing the active-reference might wake up a pending
		 * peer destruction. But bus1_active_release() has to first
		 * drop the ref, then wake up the wake-queue. Taking an rcu
		 * read lock guarantees the wake-queue (i.e., its underlying
		 * peer) is still around for the wake-up operation.
		 */
		rcu_read_lock();
		bus1_active_release(&peer->active, &peer->waitq);
		rcu_read_unlock();
	}
	return NULL;
}

#endif /* __BUS1_PEER_H */
