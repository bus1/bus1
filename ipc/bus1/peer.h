#ifndef __BUS1_PEER_H
#define __BUS1_PEER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Peers
 *
 * XXX
 */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <uapi/linux/bus1.h>
#include "pool.h"
#include "queue.h"

struct bus1_domain;
struct bus1_fs_domain;

struct bus1_peer {
	struct mutex lock;
	struct bus1_pool pool;
	struct bus1_queue queue;
};

struct bus1_peer *bus1_peer_new(struct bus1_domain *domain,
				struct bus1_cmd_connect *param);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);

int bus1_peer_ioctl(struct bus1_peer *peer,
		    struct bus1_fs_domain *fs_domain,
		    unsigned int cmd,
		    unsigned long arg);

#endif /* __BUS1_PEER_H */
