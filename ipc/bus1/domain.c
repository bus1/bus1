/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "domain.h"

struct bus1_domain_info *bus1_domain_info_new(void)
{
	struct bus1_domain_info *domain_info;

	domain_info = kmalloc(sizeof(*domain_info), GFP_KERNEL);
	if (!domain_info)
		return ERR_PTR(-ENOMEM);

	domain_info->peer_ids = 0;
	atomic64_set(&domain_info->seq_ids, 0);

	return domain_info;
}

struct bus1_domain_info *
bus1_domain_info_free(struct bus1_domain_info *domain_info)
{
	if (!domain_info)
		return NULL;

	kfree(domain_info);

	return NULL;
}
