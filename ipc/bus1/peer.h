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
 * Peers
 *
 * XXX
 */

#include <linux/atomic.h>
#include <linux/cred.h>
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

/**
 * struct bus1_peer_info - peer specific runtime information
 * @lock:			data lock
 * @rcu:			rcu
 * @cred:			user creds
 * @pid_ns:			user pid namespace
 * @user:			object owner
 * @quota:			quota handling
 * @pool:			data pool
 * @queue:			message queue, rcu-accessible
 * @map_handles_by_id:		map of owned handles, by handle id
 * @map_handles_by_node:	map of owned handles, by node pointer
 * @seqcount:			sequence counter
 * @n_dropped:			number of lost messages since last report
 * @handle_ids:			handle ID allocator
 * @n_allocated:		current amount of allocated pool memory
 * @n_messages:			current number of queue entries
 * @n_handles:			current number of handles
 */
struct bus1_peer_info {
	union {
		struct mutex lock;
		struct rcu_head rcu;
	};
	const struct cred *cred;
	struct pid_namespace *pid_ns;
	struct bus1_user *user;
	struct bus1_user_quota quota;
	struct bus1_pool pool;
	struct bus1_queue queue;
	struct rb_root map_handles_by_id;
	struct rb_root map_handles_by_node;
	struct seqcount seqcount;
	atomic_t n_dropped;
	u64 handle_ids;

	size_t n_allocated;
	size_t n_messages;
	size_t n_handles;
};

/**
 * struct bus1_peer - peer handle
 * @rcu:		rcu
 * @waitq:		peer wide wait queue
 * @active:		active references
 * @info:		underlying peer information
 */
struct bus1_peer {
	struct rcu_head rcu;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer_info __rcu *info;
};

struct bus1_peer *bus1_peer_new(void);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);
int bus1_peer_connect(struct bus1_peer *peer,
		      struct file *peer_file,
		      struct bus1_cmd_peer_create *param);
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
 * This releases an active reference to a peer, acquired previously via one
 * of the lookup functions.
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

/**
 * bus1_peer_wake() - wake up peer
 * @peer:		peer to wake up
 *
 * This wakes up a peer and notifies user-space about poll() events.
 */
static inline void bus1_peer_wake(struct bus1_peer *peer)
{
	wake_up_interruptible(&peer->waitq);
}

#endif /* __BUS1_PEER_H */
