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
 * Users
 *
 * XXX
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>

struct bus1_peer_info;
struct bus1_pool;
struct bus1_queue;

/**
 * struct bus1_user - resource accounting for users
 * @ref:		reference counter
 * @uid:		UID of the user
 * @id:			internal index of this user
 * @fds_inflight:	number of in-flight fds the user has
 * @rcu:		rcu
 */
struct bus1_user {
	struct kref ref;

	union {
		struct {
			kuid_t uid;
			unsigned int id;
			atomic_t fds_inflight;
		};
		struct rcu_head rcu;
	};
};

/**
 * struct bus1_user_stats - quota statistics between a user and a peer
 * @n_allocated:	memory in bytes used by queued messages
 * @n_messages:		number of queued messages
 * @n_handles:		number of queued handles
 */
struct bus1_user_stats {
	u32 n_allocated;
	u16 n_messages;
	u16 n_handles;
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
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid);
struct bus1_user *bus1_user_ref(struct bus1_user *user);
struct bus1_user *bus1_user_unref(struct bus1_user *user);

/* quota */
void bus1_user_quota_init(struct bus1_user_quota *quota);
void bus1_user_quota_destroy(struct bus1_user_quota *quota);
int bus1_user_quota_charge(struct bus1_peer_info *peer_info,
			   struct bus1_user *user,
			   size_t size,
			   size_t n_handles,
			   size_t n_fds);
void bus1_user_quota_discharge(struct bus1_peer_info *peer_info,
			       struct bus1_user *user,
			       size_t size,
			       size_t n_handles,
			       size_t n_fds);
void bus1_user_quota_commit(struct bus1_peer_info *peer_info,
			    struct bus1_user *user,
			    size_t size,
			    size_t n_handles,
			    size_t n_fds);

#endif /* __BUS1_USER_H */
