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
 * All operations performed on bus1 handles return negative error codes. The
 * following error codes are well-defined and used all over the place:
 *
 *   ENOMEM:            out of kernel memory
 *   EFAULT:            cannot access ioctl parameters
 *   EINVAL:            invalid parameters
 *   EMSGSIZE:          ioctl parameters are too small/large
 *   ENOTTY:            unknown ioctl
 *   ENXIO:             destination handle does not exist
 *   ESHUTDOWN:         local client was already disconnected
 *   ENOTCONN:          local client is not connected, yet
 *   EISCONN:           local client is already connected
 *   EXFULL:            target memory pool is full
 *   ENOTUNIQ:          argument is not unique
 *   ESTALE:            referenced node has no local handles
 *   EINPROGRESS:       node destruction already in progress
 *   EDQUOT:            quota exceeded
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define BUS1_VEC_MAX		(512) /* UIO_MAXIOV is 1024 */
#define BUS1_FD_MAX		(256)

#define BUS1_IOCTL_MAGIC		0x96
#define BUS1_HANDLE_INVALID		((__u64)-1)
#define BUS1_OFFSET_INVALID		((__u64)-1)

enum {
	BUS1_HANDLE_FLAG_MANAGED	= 1ULL <<  0,
	BUS1_HANDLE_FLAG_ALLOCATE	= 1ULL <<  1,
	BUS1_HANDLE_FLAG_ONESHOT	= 1ULL <<  2,
};

enum {
	BUS1_CONNECT_FLAG_CLIENT	= 1ULL <<  0,
	BUS1_CONNECT_FLAG_MONITOR	= 1ULL <<  1,
	BUS1_CONNECT_FLAG_QUERY		= 1ULL <<  2,
	BUS1_CONNECT_FLAG_RESET		= 1ULL <<  3,
};

struct bus1_cmd_connect {
	__u64 flags;
	__u64 pool_size;
	__u64 parent_handle;
	__u64 parent_fd;
} __attribute__((__aligned__(8)));

struct bus1_cmd_handle_create {
	__u64 flags;
	__u64 handle;
} __attribute__((__aligned__(8)));

enum {
	BUS1_SEND_FLAG_CONTINUE		= 1ULL <<  0,
	BUS1_SEND_FLAG_SILENT		= 1ULL <<  1,
	BUS1_SEND_FLAG_RELEASE		= 1ULL <<  2,
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
	BUS1_RECV_FLAG_PEEK		= 1ULL <<  0,
};

struct bus1_cmd_recv {
	__u64 flags;
	__u64 msg_dropped;
	__u64 msg_offset;
	__u64 msg_size;
	__u64 msg_handles;
	__u64 msg_fds;
} __attribute__((__aligned__(8)));

struct bus1_header {
	__u64 destination;
	__u32 uid;
	__u32 gid;
	__u32 pid;
	__u32 tid;
} __attribute__((__aligned__(8)));

enum {
	BUS1_CMD_CONNECT		= _IOWR(BUS1_IOCTL_MAGIC, 0x00,
						struct bus1_cmd_connect),
	BUS1_CMD_DISCONNECT		= _IOWR(BUS1_IOCTL_MAGIC, 0x01,
						__u64),
	BUS1_CMD_HANDLE_CREATE		= _IOWR(BUS1_IOCTL_MAGIC, 0x03,
						struct bus1_cmd_handle_create),
	BUS1_CMD_HANDLE_DESTROY		= _IOWR(BUS1_IOCTL_MAGIC, 0x04,
						__u64),
	BUS1_CMD_HANDLE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x05,
						__u64),
	BUS1_CMD_SLICE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x02,
						__u64),
	BUS1_CMD_SEND			= _IOWR(BUS1_IOCTL_MAGIC, 0x06,
						struct bus1_cmd_send),
	BUS1_CMD_RECV			= _IOWR(BUS1_IOCTL_MAGIC, 0x07,
						struct bus1_cmd_recv),
};

#endif /* _UAPI_LINUX_BUS1_H */
