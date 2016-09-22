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
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "user.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

struct bus1_message;

/**
 * struct bus1_peer - peer handle
 * @id:				unique peer ID
 * @flags:			peer flags
 * @cred:			user creds
 * @pid_ns:			user pid namespace
 * @user:			object owner
 * @quota:			quota handling
 * @waitq:			peer wide wait queue
 * @active:			active references
 * @debugdir:			debugfs directory, or NULL/ERR_PTR
 * @rcu:			rcu
 * @lock:			peer lock
 * @data.lock:			data lock
 * @data.pool:			data pool
 * @data.queue:			message queue, rcu-accessible
 * @data.map_handles_by_node:	map of owned handles, by node pointer
 * @local.seed:			seed message
 * @local.map_handles_by_id:	map of owned handles, by handle id
 * @local.handle_ids:		handle ID allocator
 */
struct bus1_peer {
	u64 id;
	u64 flags;
	const struct cred *cred;
	struct pid_namespace *pid_ns;
	struct bus1_user *user;
	struct bus1_user_quota quota;
	wait_queue_head_t waitq;
	struct bus1_active active;
	union {
		struct dentry *debugdir;
		struct rcu_head rcu;
	};

	struct mutex lock;

	struct {
		struct mutex lock;
		struct bus1_pool pool;
		struct bus1_queue queue;
		struct rb_root map_handles_by_node;
	} data;

	struct {
		struct mutex lock;
		struct bus1_message *seed;
		struct rb_root map_handles_by_id;
		u64 handle_ids;
	} local;
};

/**
 * struct bus1_peer_list - list of acquired peers
 * @peer:		acquired peer
 * @next:		next list element
 */
struct bus1_peer_list {
	struct bus1_peer *peer;
	void *next;
};

struct bus1_peer *bus1_peer_new(void);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);
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
 * bus1_peer_list_bind() - temporarily bind a peer of a peer list
 * @list:		entry to bind
 *
 * Whenever you deal with an unbound set of peers that must be acquired at the
 * same time, we need to work around lockdep limitations (see
 * bus1_active_lockdep_{acquired,released}() for details). The bus1_peer_list
 * object is a simple wrapper to store a list of peers. Whenever your iterate
 * that list, you call bus1_peer_list_bind() to temporarily enable lockdep
 * annotations for that single peer, and bus1_peer_list_unbind() when done.
 *
 * That is, each access to a peer in a peer-list is guarded by the bind() and
 * unbind() calls, enabling/disabling lockdep. Note that acquire() returns
 * peers bound, so after initializing a peer-list, you first have to unbind the
 * peer.
 *
 * Return: Pointer to bound peer.
 */
static inline struct bus1_peer *
bus1_peer_list_bind(struct bus1_peer_list *list)
{
	bus1_active_lockdep_acquired(&list->peer->active);
	return list->peer;
}

/**
 * bus1_peer_list_unbind() - temporarily unbind a peer of a peer list
 * @list:		entry to unbind
 *
 * See bus1_peer_list_bind() for details. This is the inverse operation.
 */
static inline void bus1_peer_list_unbind(struct bus1_peer_list *list)
{
	bus1_active_lockdep_released(&list->peer->active);
}

#endif /* __BUS1_PEER_H */
