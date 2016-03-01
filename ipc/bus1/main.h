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
 * (A)                                          # Examples:
 *  +--+ bus1_domain.active.write               #   domain teardown
 *  |                                           #
 *  +--+ bus1_domain.active.read                #   mount entry
 *     +--+ bus1_peer.rwlock.read_write         #   ioctl entry
 *        +--+ bus1_peer.active.read            #
 *        |  +--+ bus1_peer_info.lock           #   ioctl handlers
 *        |  |                                  #
 *        |  +--+ bus1_domain.seqcount.read     #   send ioctl
 *        |                                     #
 *        +--+ bus1_domain.lock                 #   peer connect/disconnect
 *           +--+ bus1_peer.active.write        #   domain teardown
 *           |                                  #
 *           +--+ bus1_domain.seqcount.write    #   domain teardown
 */

#define BUS1_IOCTL_MAX_SIZE (4096)
#define BUS1_MESSAGES_MAX (1024)

extern const struct file_operations bus1_fops;

#endif /* __BUS1_MAIN_H */
