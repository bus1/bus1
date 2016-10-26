#pragma once

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <assert.h>
#include <inttypes.h>
#include <linux/bus1.h>
#include <stdlib.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int
bus1_ioctl(int fd, unsigned int cmd, void *arg)
{
	return (ioctl(fd, cmd, arg) >= 0) ? 0: -errno;
}

static inline int
bus1_ioctl_peer_disconnect(int fd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_PEER_DISCONNECT) == sizeof(uint64_t),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_PEER_DISCONNECT, NULL);
}

static inline int
bus1_ioctl_peer_query(int fd, struct bus1_cmd_peer_reset *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_PEER_QUERY) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_PEER_QUERY, cmd);
}

static inline int
bus1_ioctl_peer_reset(int fd, struct bus1_cmd_peer_reset *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_PEER_RESET) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_PEER_RESET, cmd);
}

static inline int
bus1_ioctl_handle_release(int fd, uint64_t *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_HANDLE_RELEASE, cmd);
}

static inline int
bus1_ioctl_handle_transfer(int fd, struct bus1_cmd_handle_transfer *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_HANDLE_TRANSFER) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_HANDLE_TRANSFER, cmd);
}

static inline int
bus1_ioctl_nodes_destroy(int fd, struct bus1_cmd_nodes_destroy *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_NODES_DESTROY) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_NODES_DESTROY, cmd);
}

static inline int
bus1_ioctl_slice_release(int fd, uint64_t *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_SLICE_RELEASE, cmd);
}

static inline int
bus1_ioctl_send(int fd, struct bus1_cmd_send *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_SEND) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_SEND, cmd);
}

static inline int
bus1_ioctl_recv(int fd, struct bus1_cmd_recv *cmd)
{
	static_assert(_IOC_SIZE(BUS1_CMD_RECV) == sizeof(*cmd),
		      "ioctl is called with invalid argument size");

	return bus1_ioctl(fd, BUS1_CMD_RECV, cmd);
}

#ifdef __cplusplus
}
#endif
