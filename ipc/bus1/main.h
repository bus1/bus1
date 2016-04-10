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
 * DOC: Bus1 Overview
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
 *   b1_peer.active
 *     b1_peer_info.lock
 *       b1_peer_info.seqcount
 */

#define BUS1_MESSAGES_MAX (1024)
#define BUS1_HANDLES_MAX (16384)

extern const struct file_operations bus1_fops;

#endif /* __BUS1_MAIN_H */
