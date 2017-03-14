#ifndef __BUS1_MAIN_H
#define __BUS1_MAIN_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Bus1 Overview
 *
 * bus1 is a local IPC system, which provides a decentralized infrastructure to
 * share objects between local peers. The main building blocks are nodes and
 * handles. Nodes represent objects of a local peer, while handles represent
 * descriptors that point to a node. Nodes can be created and destroyed by any
 * peer, and they will always remain owned by their respective creator. Handles,
 * on the other hand, are used to refer to nodes and can be passed around with
 * messages as auxiliary data. Whenever a handle is transferred, the receiver
 * will get its own handle allocated, pointing to the same node as the original
 * handle.
 *
 * Any peer can send messages directed at one of their handles. This will
 * transfer the message to the owner of the node the handle points to. If a
 * peer does not posess a handle to a given node, it will not be able to send a
 * message to that node. That is, handles provide exclusive access management.
 * Anyone that somehow acquired a handle to a node is privileged to further
 * send this handle to other peers. As such, access management is transitive.
 * Once a peer acquired a handle, it cannot be revoked again. However, a node
 * owner can, at anytime, destroy a node. This will effectively unbind all
 * existing handles to that node on any peer, notifying each one of the
 * destruction.
 *
 * Unlike nodes and handles, peers cannot be addressed directly. In fact, peers
 * are completely disconnected entities. A peer is merely an anchor of a set of
 * nodes and handles, including an incoming message queue for any of those.
 * Whether multiple nodes are all part of the same peer, or part of different
 * peers does not affect the remote view of those. Peers solely exist as
 * management entity and command dispatcher to local processes.
 *
 * The set of actors on a system is completely decentralized. There is no
 * global component involved that provides a central registry or discovery
 * mechanism. Furthermore, communication between peers only involves those
 * peers, and does not affect any other peer in any way. No global
 * communication lock is taken. However, any communication is still globally
 * ordered, including unicasts, multicasts, and notifications.
 */

/**
 * Locking
 *
 * Most of the bus1 objects form a hierarchy, as such, their locks must be
 * ordered. Not all orders are explicitly defined (e.g., they might define
 * orthogonal hierarchies), but this list gives a rough overview:
 *
 *   bus1_peer.active
 *     bus1_peer.local.lock
 *       bus1_peer.data.lock
 *       bus1_user_limits.lock
 *       bus1_user_lock
 */

struct dentry;
struct file_operations;

/**
 * bus1_fops - file-operations of bus1 character devices
 *
 * All bus1 peers are backed by a character device with @bus1_fops used as
 * file-operations. That is, a file is a bus1 peer if, and only if, its f_op
 * pointer contains @bus1_fops.
 */
extern const struct file_operations bus1_fops;

/**
 * bus1_debugdir - debugfs root directory
 *
 * If debugfs is enabled, this is set to point to the debugfs root directory
 * for this module. If debugfs is disabled, or if the root directory could not
 * be created, this is set to NULL or ERR_PTR (which debugfs functions can deal
 * with seamlessly).
 */
extern struct dentry *bus1_debugdir;

#endif /* __BUS1_MAIN_H */
