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
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/wait.h>
#include "active.h"

struct bus1_domain_info {
	u64 peer_ids;
	atomic64_t seq_ids;
};

struct bus1_domain_info *bus1_domain_info_new(void);
struct bus1_domain_info *
bus1_domain_info_free(struct bus1_domain_info *domain_info);

struct bus1_domain {
	struct mutex lock;
	seqcount_t seqcount;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_domain_info *info;
	size_t n_peers;
	size_t n_names;
	struct rb_root map_peers;
	struct rb_root map_names;
};

struct bus1_domain *bus1_domain_new(void);
struct bus1_domain *bus1_domain_free(struct bus1_domain *domain);
void bus1_domain_teardown(struct bus1_domain *domain);
struct bus1_domain *bus1_domain_acquire(struct bus1_domain *domain);
struct bus1_domain *bus1_domain_release(struct bus1_domain *domain);
int bus1_domain_resolve(struct bus1_domain *domain, unsigned long arg);

#endif /* __BUS1_DOMAIN_H */
