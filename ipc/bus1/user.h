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
#include <linux/kref.h>
#include <linux/types.h>
#include <linux/uidgid.h>

struct bus1_peer;

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
};

/**
 * struct bus1_user - resource accounting for users
 * @ref:		reference counter
 * @lock:		data lock
 * @id:			internal index of this user
 * @uid:		UID of the user
 * @rcu:		rcu
 * @limits:		resource limit counters
 */
struct bus1_user {
	struct kref ref;
	struct mutex lock;
	unsigned int id;
	kuid_t uid;
	union {
		struct rcu_head rcu;
		struct bus1_user_limits limits;
	};
};

/**
 * struct bus1_user_stats - quota statistics between a user and a peer
 * @n_slices:		number of queued slices
 * @n_handles:		number of queued handles
 * @n_bytes:		memory in bytes used by queued messages
 * @n_fds:		number of queued fds
 */
struct bus1_user_stats {
	u16 n_slices;
	u16 n_handles;
	u32 n_bytes;
	u16 n_fds;
};

/**
 * struct bus1_user_quota - quota handling
 * @n_stats:		number of allocated user entries
 * @stats:		user entries
 */
struct bus1_user_quota {
	size_t n_stats;
	struct bus1_user_stats *stats;
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

/* quota */
void bus1_user_quota_init(struct bus1_user_quota *quota);
void bus1_user_quota_destroy(struct bus1_user_quota *quota);
int bus1_user_quota_charge(struct bus1_peer *peer,
			   struct bus1_user *user,
			   size_t n_bytes,
			   size_t n_handles,
			   size_t n_fds);
void bus1_user_quota_discharge(struct bus1_peer *peer,
			       struct bus1_user *user,
			       size_t n_bytes,
			       size_t n_handles,
			       size_t n_fds);
void bus1_user_quota_commit(struct bus1_peer *peer,
			    struct bus1_user *user,
			    size_t n_bytes,
			    size_t n_handles,
			    size_t n_fds);

#endif /* __BUS1_USER_H */
