#ifndef __BUS1_FILESYSTEM_H
#define __BUS1_FILESYSTEM_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Filesystem
 *
 * XXX
 */

#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include "active.h"

struct bus1_domain;
struct bus1_peer;
struct bus1_fs_domain;
struct bus1_fs_name;
struct bus1_fs_peer;

/**
 * struct bus1_fs_domain - domain handle
 * @waitq:	shared wait-queue
 * @active:	active references
 * @domain:	underlying domain
 * @rwlock:	protects lookups
 * @n_peers:	number of registered peers
 * @n_names:	number of registered names
 * @map_peers:	maps ids to peers
 * @map_names:	maps names to peers
 */
struct bus1_fs_domain {
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_domain *domain;
	struct rw_semaphore rwlock;
	size_t n_peers;
	size_t n_names;
	struct rb_root map_peers;
	struct rb_root map_names;
};

/**
 * struct bus1_fs_peer - peer handle
 * @lock:	protects handle setup/teardown
 * @waitq:	shared wait-queue
 * @active:	active reference counter
 * @peer:	connected peer
 * @names:	names of this peer
 * @rb:		rb-node into parent domain
 * @id:		id of this peer
 */
struct bus1_fs_peer {
	struct mutex lock;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer *peer;
	struct bus1_fs_name *names;
	struct rb_node rb;
	u64 id; /* protected by fs_domain->rwlock */
};

int bus1_fs_init(void);
void bus1_fs_exit(void);

struct bus1_fs_peer *
bus1_fs_peer_find_by_name(struct bus1_fs_domain *fs_domain, const char *name);
struct bus1_fs_peer *
bus1_fs_peer_find_by_id(struct bus1_fs_domain *fs_domain, __u64 id);

/**
 * bus1_fs_peer_release() - release an active reference
 * @fs_peer:	handle to release, or NULL
 *
 * This releases an active reference to a peer, acquired previously via one
 * of the lookup functions.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_fs_peer *
bus1_fs_peer_release(struct bus1_fs_peer *fs_peer)
{
	if (fs_peer)
		bus1_active_release(&fs_peer->active, &fs_peer->waitq);
	return NULL;
}

#endif /* __BUS1_FILESYSTEM_H */
