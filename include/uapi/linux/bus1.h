#ifndef _UAPI_LINUX_BUS1_H
#define _UAPI_LINUX_BUS1_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define BUS1_FD_MAX			(256)

#define BUS1_IOCTL_MAGIC		0x96
#define BUS1_HANDLE_INVALID		((__u64)-1)
#define BUS1_OFFSET_INVALID		((__u64)-1)

enum {
	BUS1_HANDLE_FLAG_MANAGED				= 1ULL <<  0,
	BUS1_HANDLE_FLAG_REMOTE					= 1ULL <<  1,
};

enum {
	BUS1_PEER_RESET_FLAG_FLUSH				= 1ULL <<  0,
	BUS1_PEER_RESET_FLAG_FLUSH_SEED				= 1ULL <<  1,
};

struct bus1_cmd_peer_reset {
	__u64 flags;
	__u64 peer_flags;
	__u32 max_slices;
	__u32 max_handles;
	__u32 max_inflight_bytes;
	__u32 max_inflight_fds;
} __attribute__((__aligned__(8)));

struct bus1_cmd_handle_transfer {
	__u64 flags;
	__u64 src_handle;
	__u64 dst_fd;
	__u64 dst_handle;
} __attribute__((__aligned__(8)));

enum {
	BUS1_NODES_DESTROY_FLAG_RELEASE_HANDLES			= 1ULL <<  0,
};

struct bus1_cmd_nodes_destroy {
	__u64 flags;
	__u64 ptr_nodes;
	__u64 n_nodes;
} __attribute__((__aligned__(8)));

enum {
	BUS1_SEND_FLAG_CONTINUE					= 1ULL <<  0,
	BUS1_SEND_FLAG_SEED					= 1ULL <<  1,
};

struct bus1_cmd_send {
	__u64 flags;
	__u64 ptr_destinations;
	__u64 ptr_errors;
	__u64 n_destinations;
	__u64 ptr_vecs;
	__u64 n_vecs;
	__u64 ptr_handles;
	__u64 n_handles;
	__u64 ptr_fds;
	__u64 n_fds;
} __attribute__((__aligned__(8)));

enum {
	BUS1_RECV_FLAG_SEED					= 1ULL <<  0,
	BUS1_RECV_FLAG_INSTALL_FDS				= 1ULL <<  1,
};

enum {
	BUS1_MSG_NONE,
	BUS1_MSG_DATA,
	BUS1_MSG_NODE_DESTROY,
	BUS1_MSG_NODE_RELEASE,
};

enum {
	BUS1_MSG_FLAG_CONTINUE					= 1ULL <<  0,
};

struct bus1_cmd_recv {
	__u64 flags;
	__u64 max_offset;
	struct {
		__u64 type;
		__u64 flags;
		__u64 destination;
		__u64 offset;
		__u64 n_bytes;
		__u64 n_handles;
		__u64 n_fds;
	} __attribute__((__aligned__(8))) msg;
} __attribute__((__aligned__(8)));

enum {
	BUS1_CMD_PEER_DISCONNECT	= _IOWR(BUS1_IOCTL_MAGIC, 0x00,
					__u64),
	BUS1_CMD_PEER_QUERY		= _IOWR(BUS1_IOCTL_MAGIC, 0x01,
					struct bus1_cmd_peer_reset),
	BUS1_CMD_PEER_RESET		= _IOWR(BUS1_IOCTL_MAGIC, 0x02,
					struct bus1_cmd_peer_reset),
	BUS1_CMD_HANDLE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x10,
					__u64),
	BUS1_CMD_HANDLE_TRANSFER	= _IOWR(BUS1_IOCTL_MAGIC, 0x11,
					struct bus1_cmd_handle_transfer),
	BUS1_CMD_NODES_DESTROY		= _IOWR(BUS1_IOCTL_MAGIC, 0x20,
					struct bus1_cmd_nodes_destroy),
	BUS1_CMD_SLICE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x30,
					__u64),
	BUS1_CMD_SEND			= _IOWR(BUS1_IOCTL_MAGIC, 0x40,
					struct bus1_cmd_send),
	BUS1_CMD_RECV			= _IOWR(BUS1_IOCTL_MAGIC, 0x50,
					struct bus1_cmd_recv),
};

#endif /* _UAPI_LINUX_BUS1_H */
