#ifndef __BUS1_MAIN_H
#define __BUS1_MAIN_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Bus1 Overview
 *
 * XXX
 */

/**
 * Locking
 *
 * Most of the bus1 objects form a hierarchy, as such, their locks must be
 * ordered. Not all orders are explicitly defined (e.g., they might define
 * orthogonal hierarchies), but this list tries to give a rough overview:
 *
 *   bus1_fs_peer.lock:
 *     bus1_fs_domain.rwlock:
 *       bus1_fs_handle.active:
 */

#define BUS1_IOCTL_MAX_SIZE (4096)

#endif /* __BUS1_MAIN_H */
