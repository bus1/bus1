#ifndef _UAPI_LINUX_BUS1_H
#define _UAPI_LINUX_BUS1_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Public Bus1 API
 *
 * This header defines the public bus1 API. If the kernel module is loaded, its
 * entry point is a single character device named 'bus1', accepting ioctls as
 * defined below.
 */

/**
 * Error Codes
 *
 * All operations performed on bus1 fds return negative error codes. The
 * following error codes are well-defined and used all over the place:
 *
 *   EAGAIN:            no messages ready to be dequeued
 *   EBADF:             invalid file-descriptor
 *   EDQUOT:            quota exceeded
 *   EFAULT:            cannot access ioctl parameters
 *   EHOSTUNREACH:      destination node has been destroyed
 *   EINVAL:            invalid ioctl parameters
 *   EMSGSIZE:          ioctl parameters are too small/large
 *   ENOMEM:            out of kernel memory
 *   ENOTTY:            unknown ioctl
 *   ENXIO:             invalid handle or slice
 *   EOPNOTSUPP:        could not pass file-descriptor of unsupported type
 *   EPERM:             permission denied to mmap pool as writable
 *   ESHUTDOWN:         local peer was already disconnected
 *   EXFULL:            target memory pool is full
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define BUS1_VEC_MAX		(512) /* UIO_MAXIOV is 1024 */
#define BUS1_FD_MAX		(256)

#define BUS1_IOCTL_MAGIC		0x96
#define BUS1_HANDLE_INVALID		((__u64)-1)
#define BUS1_OFFSET_INVALID		((__u64)-1)

enum {
	BUS1_NODE_FLAG_MANAGED		= 1ULL <<  0,
	BUS1_NODE_FLAG_ALLOCATE		= 1ULL <<  1,
	BUS1_NODE_FLAG_PERSISTENT	= 1ULL <<  2,
};

struct bus1_cmd_peer_init {
	__u64 flags;
	__u64 max_bytes;
	__u64 max_slices;
	__u64 max_handles;
	__u64 max_fds;
} __attribute__((__aligned__(8)));

struct bus1_cmd_peer_reset {
	__u64 flags;
} __attribute__((__aligned__(8)));

struct bus1_cmd_peer_clone {
	__u64 flags;
	__u64 parent_handle;
	__u64 child_handle;
	__u64 fd;
} __attribute__((__aligned__(8)));

enum {
	BUS1_SEND_FLAG_CONTINUE		= 1ULL <<  0,
	BUS1_SEND_FLAG_SEED		= 1ULL <<  1,
};

struct bus1_cmd_send {
	__u64 flags;
	__u64 ptr_destinations;
	__u64 n_destinations;
	__u64 ptr_vecs;
	__u64 n_vecs;
	__u64 ptr_handles;
	__u64 n_handles;
	__u64 ptr_fds;
	__u64 n_fds;
} __attribute__((__aligned__(8)));

enum {
	BUS1_MSG_NONE,
	BUS1_MSG_DATA,
	BUS1_MSG_NODE_DESTROY,
	BUS1_MSG_NODE_RELEASE,
};

struct bus1_msg_data {
	__u64 destination;
	__u32 uid;
	__u32 gid;
	__u32 pid;
	__u32 tid;
	__u64 offset;
	__u64 n_bytes;
	__u64 n_handles;
	__u64 n_fds;
} __attribute__((__aligned__(8)));

struct bus1_msg_node_destroy {
	__u64 handle;
} __attribute__((__aligned__(8)));

struct bus1_msg_node_release {
	__u64 handle;
} __attribute__((__aligned__(8)));

enum {
	BUS1_RECV_FLAG_PEEK		= 1ULL <<  0,
	BUS1_RECV_FLAG_SEED		= 1ULL <<  1,
};

struct bus1_cmd_recv {
	__u64 flags;
	__u64 type;
	__u64 n_dropped;
	union {
		struct bus1_msg_data data;
		struct bus1_msg_node_destroy node_destroy;
		struct bus1_msg_node_release node_release;
	};
} __attribute__((__aligned__(8)));

enum {
	BUS1_CMD_PEER_INIT		= _IOWR(BUS1_IOCTL_MAGIC, 0x00,
						struct bus1_cmd_peer_init),
	BUS1_CMD_PEER_QUERY		= _IOWR(BUS1_IOCTL_MAGIC, 0x01,
						struct bus1_cmd_peer_init),
	BUS1_CMD_PEER_RESET		= _IOWR(BUS1_IOCTL_MAGIC, 0x02,
						struct bus1_cmd_peer_reset),
	BUS1_CMD_PEER_CLONE		= _IOWR(BUS1_IOCTL_MAGIC, 0x03,
						struct bus1_cmd_peer_clone),
	BUS1_CMD_NODE_DESTROY		= _IOWR(BUS1_IOCTL_MAGIC, 0x04,
						__u64),
	BUS1_CMD_HANDLE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x05,
						__u64),
	BUS1_CMD_SLICE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x06,
						__u64),
	BUS1_CMD_SEND			= _IOWR(BUS1_IOCTL_MAGIC, 0x07,
						struct bus1_cmd_send),
	BUS1_CMD_RECV			= _IOWR(BUS1_IOCTL_MAGIC, 0x08,
						struct bus1_cmd_recv),
};

#endif /* _UAPI_LINUX_BUS1_H */
