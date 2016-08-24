#pragma once

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/*
 * Wrapper of Bus1 Kernel API
 *
 * The bus1-peer object is a small, direct wrapper of the bus1 kernel API. It
 * allows direct access to all bus1 peer features, but additionally provides
 * a limited set of helpers to avoid dealing with API extensions, peer pools,
 * and ioctl calling conventions.
 *
 * The bus1-peer API is designed for threaded access. Apart from constructors
 * and destructors, any function can be called in parallel from multiple
 * threads without any synchronization necessary (neither internally nor
 * externally). They map 1-to-1 to the kernel API, but hide the ioctl
 * marshaling. Furthermore, the API is designed to allow *multiple* different
 * contexts on the same file-descriptor, without knowing about each other.
 */

#include <assert.h>
#include <inttypes.h>
#include <linux/bus1.h>
#include <stdlib.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bus1_peer;

int bus1_peer_new_from_fd(struct bus1_peer **peerp, int fd);
int bus1_peer_new_from_path(struct bus1_peer **peerp, const char *path);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);

int bus1_peer_get_fd(struct bus1_peer *peer);
size_t bus1_peer_get_pool_size(struct bus1_peer *peer);
const void *bus1_peer_get_pool(struct bus1_peer *peer);

int bus1_peer_ioctl(struct bus1_peer *peer, unsigned int cmd, void *arg);
int bus1_peer_mmap(struct bus1_peer *peer);
int bus1_peer_disconnect(struct bus1_peer *peer);
int bus1_peer_reset(struct bus1_peer *peer);
int bus1_peer_handle_transfer(struct bus1_peer *src,
			      struct bus1_peer *dst,
			      uint64_t *src_handlep,
			      uint64_t *dst_handlep);

int bus1_peer_handle_release(struct bus1_peer *peer, uint64_t handle);
int bus1_peer_slice_release(struct bus1_peer *peer, uint64_t offset);

const void *bus1_peer_slice_from_offset(struct bus1_peer *peer,
					  uint64_t offset);
uint64_t bus1_peer_slice_to_offset(struct bus1_peer *peer,
				   const void *slice);

/* inline helpers */

static inline void bus1_peer_freep(struct bus1_peer **peer)
{
	if (*peer)
		bus1_peer_free(*peer);
}

static inline int bus1_peer_nodes_destroy(struct bus1_peer *peer,
					struct bus1_cmd_nodes_destroy *destroy)
{
	static_assert(_IOC_SIZE(BUS1_CMD_NODES_DESTROY) == sizeof(*destroy),
		      "ioctl is called with invalid argument size");

	return bus1_peer_ioctl(peer, BUS1_CMD_NODES_DESTROY, destroy);
}

static inline int bus1_peer_send(struct bus1_peer *peer,
				 struct bus1_cmd_send *send)
{
	static_assert(_IOC_SIZE(BUS1_CMD_SEND) == sizeof(*send),
		      "ioctl is called with invalid argument size");

	return bus1_peer_ioctl(peer, BUS1_CMD_SEND, send);
}

static inline int bus1_peer_recv(struct bus1_peer *peer,
				 struct bus1_cmd_recv *recv)
{
	static_assert(_IOC_SIZE(BUS1_CMD_RECV) == sizeof(*recv),
		      "ioctl is called with invalid argument size");

	return bus1_peer_ioctl(peer, BUS1_CMD_RECV, recv);
}

#ifdef __cplusplus
}
#endif
