#ifndef __BUS1_PEER_H
#define __BUS1_PEER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Peers
 *
 * XXX
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "pool.h"
#include "queue.h"
#include "user.h"

struct bus1_message;

/**
 * struct bus1_peer_info - peer specific runtime information
 * @rcu:			rcu
 * @lock:			data lock
 * @cred:			user creds
 * @pid_ns:			user pid namespace
 * @cgroup_ns:			cgroup namespace
 * @user:			object owner
 * @quota:			quota handling
 * @pool:			data pool
 * @queue:			message queue, rcu-accessible
 * @map_handles_by_id:		map of owned handles, by handle id
 * @map_handles_by_node:	map of owned handles, by node pointer
 * @seqcount:			sequence counter
 * @handle_ids:			handle ID allocator
 */
struct bus1_peer_info {
	union {
		struct rcu_head rcu;
		struct mutex lock;
	};
	const struct cred *cred;
	struct pid_namespace *pid_ns;
	struct cgroup_namespace *cgroup_ns;
	struct bus1_user *user;
	struct bus1_user_quota quota;
	struct bus1_pool pool;
	struct bus1_queue queue;
	struct rb_root map_handles_by_id;
	struct rb_root map_handles_by_node;
	struct seqcount seqcount;
	u64 handle_ids;
};

/**
 * struct bus1_peer - peer handle
 * @rcu:		rcu
 * @debugdir:		debugfs directory, or NULL/ERR_PTR
 * @waitq:		peer wide wait queue
 * @active:		active references
 * @info:		underlying peer information
 * @id:			unique peer ID
 */
struct bus1_peer {
	union {
		struct rcu_head rcu;
		struct dentry *debugdir;
	};
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer_info __rcu *info;
	u64 id;
};

struct bus1_peer *bus1_peer_new(void);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);
int bus1_peer_connect(struct bus1_peer *peer);
int bus1_peer_disconnect(struct bus1_peer *peer);
int bus1_peer_ioctl(struct bus1_peer *peer,
		    unsigned int cmd,
		    unsigned long arg);

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

/**
 * bus1_peer_dereference() - dereference a peer handle
 * @peer:	handle to dereference
 *
 * Dereference a peer handle to get access to the underlying peer object. This
 * function simply returns the pointer to the linked peer information object,
 * which then can be accessed directly by the caller. The caller must hold an
 * active reference to the handle, and retain it as long as the peer object is
 * used.
 *
 * You are perfectly free to access @peer->info directly, if you are aware of
 * the lifetime restrictions. This function provides lockdep-annotations to
 * protect against gross misuse.
 *
 * Return: Pointer to the underlying peer information object is returned.
 */
static inline struct bus1_peer_info *
bus1_peer_dereference(struct bus1_peer *peer)
{
	return rcu_dereference_protected(peer->info,
					 lockdep_is_held(&peer->active));
}

#endif /* __BUS1_PEER_H */
