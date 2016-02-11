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
 * This header defines the public bus1 API. If the kernel module is loaded, a
 * filesystem, dubbed `bus1fs', is provided. It provides entry points for all
 * clients. This header defines the ioctls, etc. that can be performed on those
 * entry points.
 */

/**
 * Error Codes
 *
 * All operations performed on bus1 handles return negative error codes. The
 * following error codes are well-defined and used all over the place:
 *
 *   ENOTTY:            unknown ioctl
 *   ESHUTDOWN:         local handle was already disconnected
 *   ENOMEM:            out of kernel memory
 *   EFAULT:            cannot access ioctl parameters
 *   EMSGSIZE:          ioctl parameters are too small/large
 *   EINVAL:            invalid parameters
 *   EISNAM:            name is already in use
 *   ENXIO:             referenced object does not exist
 *   EXFULL:            target memory pool is full
 *   ENOTCONN:          handle is not connected, yet
 *   EISCONN:           handle is already connected
 *   ENOTUNIQ:          argument is not unique
 *   ELOOP:             argument points back to itself
 *   EALREADY:          operation already in progress
 *   ESTALE:            referenced node has no local handles
 *   EINPROGRESS:       handle destruction already in progress
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define BUS1_NAME_MAX_SIZE	(256) /* including terminating 0 */
#define BUS1_VEC_MAX		(512) /* UIO_MAXIOV is 1024 */
#define BUS1_FD_MAX		(256)

#define BUS1_IOCTL_MAGIC		0x96
#define BUS1_ID_INVALID			((__u64)-1)
#define BUS1_OFFSET_INVALID		((__u64)-1)
#define BUS1_FLAG_NEGOTIATE		(1ULL << 63)

enum {
	BUS1_CONNECT_FLAG_PEER		= 1ULL <<  0,
	BUS1_CONNECT_FLAG_MONITOR	= 1ULL <<  1,
	BUS1_CONNECT_FLAG_QUERY		= 1ULL <<  2,
	BUS1_CONNECT_FLAG_RESET		= 1ULL <<  3,
};

struct bus1_cmd_connect {
	__u64 size;
	__u64 flags;
	__u64 pool_size;
	char names[];
} __attribute__((__aligned__(8)));

struct bus1_cmd_resolve {
	__u64 size;
	__u64 flags;
	__u64 id;
	char name[];
} __attribute__((__aligned__(8)));

enum {
	BUS1_SEND_FLAG_IGNORE_UNKNOWN	= 1ULL <<  0,
	BUS1_SEND_FLAG_CONVEY_ERRORS	= 1ULL <<  1,
};

struct bus1_cmd_send {
	__u64 flags;
	__u64 ptr_destinations;
	__u64 n_destinations;
	__u64 ptr_vecs;
	__u64 n_vecs;
	__u64 ptr_fds;
	__u64 n_fds;
} __attribute__((__aligned__(8)));

enum {
	BUS1_RECV_FLAG_PEEK		= 1ULL <<  0,
};

struct bus1_cmd_recv {
	__u64 flags;
	__u64 msg_offset;
	__u64 msg_size;
	__u64 msg_fds;
} __attribute__((__aligned__(8)));

enum {
	BUS1_CMD_CONNECT		= _IOWR(BUS1_IOCTL_MAGIC, 0x00,
						struct bus1_cmd_connect),
	BUS1_CMD_DISCONNECT		= _IOWR(BUS1_IOCTL_MAGIC, 0x01,
						__u64),
	BUS1_CMD_SLICE_RELEASE		= _IOWR(BUS1_IOCTL_MAGIC, 0x02,
						__u64),
	BUS1_CMD_RESOLVE		= _IOWR(BUS1_IOCTL_MAGIC, 0x03,
						struct bus1_cmd_resolve),
	BUS1_CMD_SEND			= _IOWR(BUS1_IOCTL_MAGIC, 0x06,
						struct bus1_cmd_send),
	BUS1_CMD_RECV			= _IOWR(BUS1_IOCTL_MAGIC, 0x07,
						struct bus1_cmd_recv),
};

#endif /* _UAPI_LINUX_BUS1_H */
