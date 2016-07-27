#ifndef __BUS1_USER_H
#define __BUS1_USER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
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
 * fairly distribute available resources. That is, each transmission is seen by
 * bus1 as a transmission of resources from a UID to a peer. Any transmitted
 * resources are thus limited by a quota object that represents the combination
 * of the sending UID and the receiving peer. This means, regardless how many
 * different peers a possibly malicious user creates, they are accounted to the
 * same limits. So whenever a UID transmits resources to a peer, it gets access
 * to a dynamically calculated subset of the receiver's resource limits. But it
 * never gets access to the entire resource space, so it cannot exhaust the
 * resource limits of the receiver, but only its own quota on those resource
 * limits.
 */

#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/types.h>
#include <linux/uidgid.h>

struct bus1_peer_info;

/**
 * struct bus1_user - resource accounting for users
 * @ref:		reference counter
 * @id:			internal index of this user
 * @uid:		UID of the user
 * @rcu:		rcu
 * @n_messages:		number of remaining quota for owned messages
 * @n_handles:		number of remaining quota for owned handles
 * @n_fds:		number of remaining quota for inflight FDs
 * @max_messages:	maximum number of owned messages
 * @max_handles:	maximum number of owned handles
 * @max_fds:		maximum number of inflight FDs
 */
struct bus1_user {
	struct kref ref;
	unsigned int id;
	kuid_t uid;

	union {
		struct rcu_head rcu;
		struct {
			atomic_t n_bytes;
			atomic_t n_slices;
			atomic_t n_handles;
			atomic_t n_fds;
			atomic_t max_bytes;
			atomic_t max_slices;
			atomic_t max_handles;
			atomic_t max_fds;
		};
	};
};

/**
 * struct bus1_user_stats - quota statistics between a user and a peer
 * @n_bytes:		memory in bytes used by queued messages
 * @n_slices:		number of queued slices
 * @n_handles:		number of queued handles
 * @n_fds:		number of queued fds
 */
struct bus1_user_stats {
	u32 n_bytes;
	u16 n_slices;
	u16 n_handles;
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

/* users */
void bus1_user_exit(void);
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid);
struct bus1_user *bus1_user_ref(struct bus1_user *user);
struct bus1_user *bus1_user_unref(struct bus1_user *user);

/* quota */
void bus1_user_quota_init(struct bus1_user_quota *quota);
void bus1_user_quota_destroy(struct bus1_user_quota *quota);
int bus1_user_quota_charge(struct bus1_peer_info *peer_info,
			   struct bus1_user *user,
			   size_t n_bytes,
			   size_t n_handles,
			   size_t n_fds);
void bus1_user_quota_discharge(struct bus1_peer_info *peer_info,
			       struct bus1_user *user,
			       size_t n_bytes,
			       size_t n_handles,
			       size_t n_fds);
void bus1_user_quota_commit(struct bus1_peer_info *peer_info,
			    struct bus1_user *user,
			    size_t n_bytes,
			    size_t n_handles,
			    size_t n_fds);

void bus1_user_quota_release_slices(struct bus1_peer_info *peer_info,
				    size_t n_slices);

#endif /* __BUS1_USER_H */
