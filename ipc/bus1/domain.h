#ifndef __BUS1_DOMAIN_H
#define __BUS1_DOMAIN_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Domains
 *
 * XXX
 */

#include <linux/atomic.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>
#include "active.h"

/**
 * struct bus1_domain_info - domain specific runtime information
 * @lock:		data lock
 * @peer_ids:		counter for peer ID allocations
 * @seq_ids:		counter for transaction ID allocations
 * @user_idr:		mapping from uids to bus1_user objects
 * @user_ns:		owning user namespace of this domain
 *
 * This object contains all runtime data of a domain, which is not required in
 * the handle object. That is, any data stored in this object will be
 * deallocated as soon as a domain is torn down (even though there might still
 * be handles around).
 */
struct bus1_domain_info {
	struct mutex lock;
	u64 peer_ids;
	atomic64_t seq_ids;
	struct idr user_idr;
	struct user_namespace *user_ns;
};

/**
 * struct bus1_domain - domain handles
 * @lock:		data lock
 * @active:		active references
 * @seqcount:		lookup sequence counter
 * @waitq:		domain-wide wait queue
 * @info:		underlying domain information
 * @n_peers:		number of linked peers
 * @n_names:		number of linked names
 * @map_peers:		linked peers
 * @map_names:		linked names
 *
 * This object represents a handle to a domain. The handle always outlives the
 * underlying domain and is used to gate access to the domain. The handle
 * provides an active-reference counter to guard access to @info (which
 * contains the actual domain).
 *
 * The lookup maps (@map_peers and @map_names) actually belong into
 * bus1_domain_info, but for performance reasons they're kept in the handle.
 * Their write side is protected by @lock, the read side is protected by
 * @seqcount and RCU.
 */
struct bus1_domain {
	struct mutex lock;
	struct bus1_active active;
	seqcount_t seqcount;
	wait_queue_head_t waitq;
	struct bus1_domain_info *info;
	size_t n_peers;
	size_t n_names;
	struct rb_root map_peers;
	struct rb_root map_names;
};

struct bus1_domain *bus1_domain_new(struct user_namespace *user_ns);
struct bus1_domain *bus1_domain_free(struct bus1_domain *domain);
void bus1_domain_teardown(struct bus1_domain *domain);
struct bus1_domain *bus1_domain_acquire(struct bus1_domain *domain);
struct bus1_domain *bus1_domain_release(struct bus1_domain *domain);

#endif /* __BUS1_DOMAIN_H */
