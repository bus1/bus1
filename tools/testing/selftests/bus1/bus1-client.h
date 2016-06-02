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
 * The bus1-client object is a small, direct wrapper of the bus1 kernel API. It
 * allows direct access to all bus1 client features, but additionally provides
 * a limited set of helpers to avoid dealing with API extensions, client pools,
 * and ioctl calling convetions.
 *
 * The bus1-client API is designed for threaded access. Apart from constructors
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

struct bus1_client;

#define BUS1_CLIENT_POOL_SIZE (32ULL * 1024ULL * 1024ULL)

int bus1_client_new_from_fd(struct bus1_client **clientp, int fd);
int bus1_client_new_from_path(struct bus1_client **clientp, const char *path);
struct bus1_client *bus1_client_free(struct bus1_client *client);

int bus1_client_get_fd(struct bus1_client *client);
size_t bus1_client_get_pool_size(struct bus1_client *client);
void *bus1_client_get_pool(struct bus1_client *client);

int bus1_client_ioctl(struct bus1_client *client, unsigned int cmd, void *arg);
int bus1_client_query(struct bus1_client *client, size_t *pool_sizep);
int bus1_client_mmap(struct bus1_client *client);
int bus1_client_init(struct bus1_client *client, size_t pool_size);
int bus1_client_clone(struct bus1_client *client,
		      uint64_t *parent_handlep,
		      uint64_t *child_handlep,
		      int *fdp,
		      size_t pool_size);

int bus1_client_node_destroy(struct bus1_client *client, uint64_t handle);
int bus1_client_handle_release(struct bus1_client *client, uint64_t handle);
int bus1_client_slice_release(struct bus1_client *client, uint64_t offset);

void *bus1_client_slice_from_offset(struct bus1_client *client,
				    uint64_t offset);
uint64_t bus1_client_slice_to_offset(struct bus1_client *client,
				     const void *slice);

/* inline helpers */

static inline void bus1_client_freep(struct bus1_client **client)
{
	if (*client)
		bus1_client_free(*client);
}

static inline int bus1_client_send(struct bus1_client *client,
				   struct bus1_cmd_send *send) {
	int r;

	static_assert(_IOC_SIZE(BUS1_CMD_SEND) == sizeof(*send),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_SEND, send);
	if (r < 0)
		return r;

	return 0;
}

static inline int bus1_client_recv(struct bus1_client *client,
				   struct bus1_cmd_recv *recv) {
	int r;

	static_assert(_IOC_SIZE(BUS1_CMD_RECV) == sizeof(*recv),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_RECV, recv);
	if (r < 0)
		return r;

	return 0;
}

#ifdef __cplusplus
}
#endif
