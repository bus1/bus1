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
 *   bus1_peer.active
 *     bus1_peer.waitq.lock
 *     bus1_peer_info.lock
 *       bus1_peer_info.seqcount
 *       bus1_user_lock
 */

/**
 * BUS1_MESSAGES_MAX - default limit for maximum number of messages
 *
 * This defines the default message limit for each user and peer. This is just
 * the default, limits can be adjusted at runtime, if required.
 *
 * The message-limit controls the number of message a peer can have assigned.
 * They are accounted on SEND and deaccounted on final release. Queuing
 * messages on a remote peer is subject to quotas.
 */
#define BUS1_MESSAGES_MAX (16383)

/**
 * BUS1_HANDLES_MAX - default limit for maximum number of handles
 *
 * This defines the default handle limit for each user and peer. This is just
 * the default, limits can be adjusted at runtime, if required.
 *
 * The handle-limit controls how many handles can be allocated on an ID-space.
 * They are accounted on creation (usually SEND), and deaccounted once released
 * (usually via RELEASE). Remote handle creation is subject to quotas, local
 * handle creation is not.
 */
#define BUS1_HANDLES_MAX (65535)

/**
 * BUS1_FDS_MAX - default limit for inflight FDs
 *
 * This defines the default inflight FD limit for each user and peer. This is
 * just the default, limits can be adjusted at runtime, if required.
 *
 * The FD-limit controls how many inflight FDs are allowed. It is accounted for
 * on SEND, and de-accounted on RECV. After RECV it is subject to RLIM_NOFILE
 * and under full control of the receiver. All inflight FD accounting is
 * accounting is subject to quotas.
 */
#define BUS1_FDS_MAX (65535)

extern const struct file_operations bus1_fops;

#endif /* __BUS1_MAIN_H */
