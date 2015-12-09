/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include "domain.h"

struct bus1_domain *bus1_domain_new(void)
{
	struct bus1_domain *domain;

	domain = kmalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	domain->peer_ids = 0;

	return domain;
}

struct bus1_domain *bus1_domain_free(struct bus1_domain *domain)
{
	if (!domain)
		return NULL;

	kfree(domain);

	return NULL;
}
