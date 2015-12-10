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
 * Domains and peers are dynamic objects, which form a hierarchy and have
 * several interactions between each other. Any part of the hierarchy may be
 * torn down at runtime, hence, we must always pin any object we're interacting
 * with. Therefore, the filesystem layer implements filesystem handles, which
 * wrap the actual underlying objects. Those handles have lifetimes that are
 * controlled by user-space, as such, they might outlive the object they link
 * to. The filesystem layer hides those handles from the rest of the bus
 * implementation and makes sure whenever user-space enters an operation, the
 * requested handles are pinned and cannot vanish until they finished the
 * operation.
 *
 * Each bus1_fs_* handle manages exactly one bus1_* object equivalent. However,
 * the handle can be deactivated at any time, and then drained (waiting for all
 * pending operations to finish). Once drained, the managed bus1_* object is
 * destroyed and any further request on the handle will fail.
 * This logic simplifies the implementation of all bus1_* objects
 * significantly. They can always rely on their context to own/pin the given
 * object, and must not take care of any references themselves. Additionally,
 * even if user-space refused to close their file-descriptors, we're still able
 * to tear down their objects, *and* free the actual object memory. Only the
 * handles themselves (which are pretty small) will stay around.
 */

#include <linux/kernel.h>

struct bus1_peer;
struct bus1_fs_domain;
struct bus1_fs_peer;

int bus1_fs_init(void);
void bus1_fs_exit(void);

struct bus1_fs_peer *
bus1_fs_peer_acquire_by_id(struct bus1_fs_domain *fs_domain, u64 id);
struct bus1_fs_peer *
bus1_fs_peer_acquire_by_name(struct bus1_fs_domain *fs_domain,
			     const char *name, u64 *out_id);
struct bus1_fs_peer *bus1_fs_peer_release(struct bus1_fs_peer *fs_peer);
struct bus1_peer *bus1_fs_peer_dereference(struct bus1_fs_peer *fs_peer);

#endif /* __BUS1_FILESYSTEM_H */
