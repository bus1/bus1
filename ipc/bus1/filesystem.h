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
 * The filesystem layer provides the public bus1 API. It implements a
 * pseudo-filesystem that can be mounted by user-space to create new domains
 * and connect new peers to the bus. Most of the actual API calls are forwarded
 * to the domain/peer/etc. objects, the filesystem layer just provides the
 * user-visiable layers and validates the input.
 *
 * Each time the filesystem is mounted, a new superblock is created and a fresh
 * bus1-domain is associated with it. Each domain is independent of the others,
 * and has no effect on anything but its own peers. Bind-mounts allow mirroring
 * an existing mount at another filesystem location.
 *
 * A mounted filesystem exposes a directory with a single entry, a file called
 * `bus'. This file represents the bus of this domain. For each open file
 * description on this entry, a bus1 peer is created. It can be controlled via
 * ioctls on the file descriptor.
 */

#include <linux/fs.h>
#include <linux/kernel.h>

extern const struct file_operations bus1_fs_bus_fops;

int bus1_fs_init(void);
void bus1_fs_exit(void);

#endif /* __BUS1_FILESYSTEM_H */
