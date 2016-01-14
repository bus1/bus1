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

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include "active.h"
#include "pool.h"
#include "queue.h"

struct bus1_domain;
struct bus1_peer_name;

/**
 * struct bus1_peer_info - peer specific runtime information
 * @lock:	data lock
 * @rcu:	rcu
 * @pool:	data pool
 * @queue:	message queue, rcu-accessible
 */
struct bus1_peer_info {
	union {
		struct mutex lock;
		struct rcu_head rcu;
	};
	struct bus1_pool pool;
	struct bus1_queue queue;
};

#define bus1_peer_info_from_pool(_pool) \
	container_of((_pool), struct bus1_peer_info, pool)
#define bus1_peer_info_from_queue(_queue) \
	container_of((_queue), struct bus1_peer_info, queue)

struct bus1_peer_info *bus1_peer_info_new(struct bus1_cmd_connect *param);
struct bus1_peer_info *bus1_peer_info_free(struct bus1_peer_info *peer_info);
void bus1_peer_info_reset(struct bus1_peer_info *peer_info, u64 id);

/**
 * struct bus1_peer - peer handle
 * @rwlock:		runtime lock
 * @waitq:		peer wide wait queue
 * @active:		active references
 * @info:		underlying peer information
 * @names:		owned names
 * @rb:			link into domain
 * @rcu:		rcu
 * @id:			peer ID
 */
struct bus1_peer {
	struct rw_semaphore rwlock;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer_info __rcu *info;
	struct bus1_peer_name *names;
	struct rb_node rb;
	struct rcu_head rcu;
	u64 id;
};

struct bus1_peer *bus1_peer_new(void);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);
int bus1_peer_teardown(struct bus1_peer *peer, struct bus1_domain *domain);
void bus1_peer_teardown_domain(struct bus1_peer *peer,
			       struct bus1_domain *domain);
struct bus1_peer *bus1_peer_acquire(struct bus1_peer *peer);
struct bus1_peer *bus1_peer_acquire_by_id(struct bus1_domain *domain, u64 id);
struct bus1_peer *bus1_peer_release(struct bus1_peer *peer);
struct bus1_peer_info *bus1_peer_dereference(struct bus1_peer *peer);
int bus1_peer_ioctl(struct bus1_peer *peer,
		    struct bus1_domain *domain,
		    unsigned int cmd,
		    unsigned long arg,
		    bool is_compat);

#endif /* __BUS1_PEER_H */
