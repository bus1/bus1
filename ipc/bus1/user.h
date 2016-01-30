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

#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include "domain.h"

/**
 * struct bus1_user - resource accounting for users
 * @ref:		Reference counter
 * @domain_info:	Domain of the user
 * @uid:		UID of the user
 * @rcu:		rcu
 */
struct bus1_user {
	struct kref ref;
	struct bus1_domain_info *domain_info;
	union {
		kuid_t uid;
		struct rcu_head rcu;
	};
};

struct bus1_user *bus1_user_acquire(struct bus1_domain *domain, kuid_t uid);
struct bus1_user *bus1_user_release(struct bus1_user *user);

#endif /* __BUS1_USER_H */
