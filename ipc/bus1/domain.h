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

#include <linux/kernel.h>

struct bus1_domain {
	u64 peer_ids;
};

struct bus1_domain *bus1_domain_new(void);
struct bus1_domain *bus1_domain_free(struct bus1_domain *domain);

#endif /* __BUS1_DOMAIN_H */
