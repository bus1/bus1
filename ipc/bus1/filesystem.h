#ifndef __BUS1_FILESYSTEM_H
#define __BUS1_FILESYSTEM_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Filesystem
 *
 * XXX
 */

#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include "active.h"

struct bus1_domain;
struct bus1_peer;
struct bus1_fs_domain;
struct bus1_fs_name;
struct bus1_fs_peer;

int bus1_fs_init(void);
void bus1_fs_exit(void);

struct bus1_fs_peer *
bus1_fs_peer_find_by_id(struct bus1_fs_domain *fs_domain, u64 id);
struct bus1_fs_peer *
bus1_fs_peer_find_by_name(struct bus1_fs_domain *fs_domain, const char *name,
			  u64 *out_id);
struct bus1_fs_peer *bus1_fs_peer_release(struct bus1_fs_peer *fs_peer);

#endif /* __BUS1_FILESYSTEM_H */
