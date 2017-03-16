#ifndef __BUS1_USER_H
#define __BUS1_USER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Users
 *
 * Different users can communicate via bus1, and many resources are shared
 * between multiple users. The bus1_user object represents the UID of a user,
 * like "struct user_struct" does in the kernel core. It is used to account
 * global resources, apply limits, and calculate quotas if different UIDs
 * communicate with each other.
 *
 * All dynamic resources have global per-user limits, which cannot be exceeded
 * by a user. They prevent a single user from exhausting local resources. Each
 * peer that is created is always owned by the user that initialized it. All
 * resources allocated on that peer are accounted on that pinned user.
 * Additionally to global resources, there are local limits per peer, that can
 * be controlled by each peer individually (e.g., specifying a maximum pool
 * size). Those local limits allow a user to distribute the globally available
 * resources across its peer instances.
 *
 * Since bus1 allows communication across UID boundaries, any such transmission
 * of resources must be properly accounted. Bus1 employs dynamic quotas to
 * fairly distribute available resources. Those quotas make sure that available
 * resources of a peer cannot be exhausted by remote UIDs, but are fairly
 * divided among all communicating peers.
 */

#include <linux/atomic.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include "util.h"

/**
 * struct bus1_user_usage - usage counters
 * @n_slices:			number of used slices
 * @n_handles:			number of used handles
 * @n_bytes:			number of used bytes
 * @n_fds:			number of used fds
 */
struct bus1_user_usage {
	atomic_t n_slices;
	atomic_t n_handles;
	atomic_t n_bytes;
	atomic_t n_fds;
};

/**
 * struct bus1_user_limits - resource limit counters
 * @n_slices:			number of remaining quota for owned slices
 * @n_handles:			number of remaining quota for owned handles
 * @n_inflight_bytes:		number of remaining quota for inflight bytes
 * @n_inflight_fds:		number of remaining quota for inflight FDs
 * @max_slices:			maximum number of owned slices
 * @max_handles:		maximum number of owned handles
 * @max_inflight_bytes:		maximum number of inflight bytes
 * @max_inflight_fds:		maximum number of inflight FDs
 * @lock:			object lock
 * @usages:			idr of usage entries per uid
 */
struct bus1_user_limits {
	atomic_t n_slices;
	atomic_t n_handles;
	atomic_t n_inflight_bytes;
	atomic_t n_inflight_fds;
	unsigned int max_slices;
	unsigned int max_handles;
	unsigned int max_inflight_bytes;
	unsigned int max_inflight_fds;
	struct mutex lock;
	struct idr usages;
	atomic_t n_usages;
};

/**
 * struct bus1_user - resource accounting for users
 * @ref:		reference counter
 * @uid:		UID of the user
 * @rcu:		rcu
 * @limits:		resource limit counters
 */
struct bus1_user {
	struct kref ref;
	kuid_t uid;
	union {
		struct rcu_head rcu;
		struct bus1_user_limits limits;
	};
};

/* module cleanup */
void bus1_user_modexit(void);

/* limits */
void bus1_user_limits_init(struct bus1_user_limits *limits,
			   struct bus1_user *source);
void bus1_user_limits_deinit(struct bus1_user_limits *limits);

/* users */
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid);
struct bus1_user *bus1_user_ref(struct bus1_user *user);
struct bus1_user *bus1_user_unref(struct bus1_user *user);

/* charges */
int bus1_user_charge(atomic_t *global, atomic_t *local, int charge);
void bus1_user_discharge(atomic_t *global, atomic_t *local, int charge);
int bus1_user_charge_quota(struct bus1_user *user,
			   struct bus1_user *actor,
			   int n_slices,
			   int n_handles,
			   int n_bytes,
			   int n_fds);
void bus1_user_discharge_quota(struct bus1_user *user,
			       struct bus1_user *actor,
			       int n_slices,
			       int n_handles,
			       int n_bytes,
			       int n_fds);
void bus1_user_commit_quota(struct bus1_user *user,
			    struct bus1_user *actor,
			    int n_slices,
			    int n_handles,
			    int n_bytes,
			    int n_fds);

#endif /* __BUS1_USER_H */
