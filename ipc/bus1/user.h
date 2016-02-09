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

struct bus1_domain;
struct bus1_domain_info;
struct bus1_pool;
struct bus1_queue;

/**
 * struct bus1_user - resource accounting for users
 * @ref:		reference counter
 * @uid:		UID of the user
 * @id:			internal index of this user
 * @fds_inflight:	number of in-flight fds the user has in this domain
 * @domain_info:	domain of the user
 * @rcu:		rcu
 */
struct bus1_user {
	struct kref ref;
	union {
		struct {
			kuid_t uid;
			unsigned int id;
			atomic_t fds_inflight;
			struct bus1_domain_info *domain_info;
		};
		struct rcu_head rcu;
	};
};

/**
 * struct bus1_user_quota - quota usage of a user in a peer
 * @memory:		memory in bytes used by queued messages
 * @messages:		number of queued messages
 */
struct bus1_user_quota {
	u32 allocated_size;
	u16 n_messages;
};

struct bus1_user *
bus1_user_acquire_by_uid(struct bus1_domain *domain, kuid_t uid);
struct bus1_user *bus1_user_release(struct bus1_user *user);
struct bus1_user *bus1_user_acquire(struct bus1_user *user);

int bus1_user_quotas_ensure_allocated(struct bus1_user_quota **quotasp,
				      size_t *n_quotasp, unsigned int id);
void bus1_user_quotas_destroy(struct bus1_user_quota **quotasp,
			      size_t *n_quotasp);

int bus1_user_quota_check(struct bus1_user_quota *quota, size_t size,
			  struct bus1_pool *pool,
			  struct bus1_queue *queue);
#endif /* __BUS1_USER_H */
