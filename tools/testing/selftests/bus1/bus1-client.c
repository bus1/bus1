/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bus1.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include "bus1-client.h"

struct bus1_client {
	int fd;
	void *pool;
	size_t pool_size;
};

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _likely_(_x) (__builtin_expect(!!(_x), 1))
#define _public_ __attribute__((__visibility__("default")))
#define _unlikely_(_x) (__builtin_expect(!!(_x), 0))

_public_ int bus1_client_new_from_fd(struct bus1_client **clientp, int fd)
{
	_cleanup_(bus1_client_freep) struct bus1_client *client = NULL;

	assert(fd >= 0);

	client = malloc(sizeof(*client));
	if (!client)
		return -ENOMEM;

	client->fd = fd;
	client->pool = NULL;
	client->pool_size = 0;

	*clientp = client;
	client = NULL;
	return 0;
}

_public_ int bus1_client_new_from_path(struct bus1_client **clientp,
				       const char *path)
{
	int r, fd;

	if (!path)
		path = "/dev/bus1";

	fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	r = bus1_client_new_from_fd(clientp, fd);
	if (r < 0)
		close(fd);

	return r;
}

_public_ struct bus1_client *bus1_client_free(struct bus1_client *client)
{
	if (!client)
		return NULL;

	if (client->pool)
		munmap(client->pool, client->pool_size);

	close(client->fd);
	free(client);

	return NULL;
}

_public_ int bus1_client_get_fd(struct bus1_client *client)
{
	return client ? client->fd : -1;
}

_public_ size_t bus1_client_get_pool_size(struct bus1_client *client)
{
	return client ? client->pool_size : 0;
}

_public_ void *bus1_client_get_pool(struct bus1_client *client)
{
	return client ? client->pool : NULL;
}

_public_ int bus1_client_ioctl(struct bus1_client *client,
			       unsigned int cmd,
			       void *arg)
{
	int r;

	r = ioctl(client->fd, cmd, arg);
	return r >= 0 ? r : -errno;
}

_public_ int bus1_client_query(struct bus1_client *client, size_t *pool_sizep)
{
	struct bus1_cmd_peer_init peer_init;
	int r;

	if (_likely_(client->pool_size > 0)) {
		*pool_sizep = client->pool_size;
		return 0;
	}

	peer_init.flags = 0;
	peer_init.pool_size = 0;

	static_assert(_IOC_SIZE(BUS1_CMD_PEER_QUERY) == sizeof(peer_init),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_PEER_QUERY, &peer_init);
	if (r < 0)
		return r;

	assert(peer_init.pool_size != 0);

	*pool_sizep = peer_init.pool_size;
	return 0;
}

_public_ int bus1_client_mmap(struct bus1_client *client)
{
	const void *pool, *old_pool;
	size_t pool_size, old_size;
	int r;

	r = bus1_client_query(client, &pool_size);
	if (r < 0)
		return r;

	/*
	 * MMap the pool of @client with size @pool_size. Note that this might
	 * be called in parallel on multiple threads. However, we got
	 * @pool_size from the kernel, so it is guaranteed to never change.
	 *
	 * We first acquire @pool and see whether it is set. If it is, we know
	 * we are already done so we simply bail out. If it is not set (i.e.,
	 * it equals NULL), we have to map it. We then first write the
	 * pool-size atomically on the client. If we race anyone else, we don't
	 * care since everyone would write the same pool-size. Next, we write
	 * the mapping-pointer. We must do this atomically and verify that we
	 * replace the previous NULL. If we didn't replace it, we raced
	 * another mmap() so we unmap our temporary map and acquire theirs (via
	 * __ATOMIC_ACQUIRE on the failure path). If we successfully replaced
	 * it, we are in-sync and can return (but we must write it via
	 * __ATOMIC_RELEASE, to sync it with any racing __atomic_load()
	 * fast-path).
	 */

	assert(pool_size > 0);
	assert(pool_size < (uint64_t)-1);

	/* fastpath: sync'ed with atomic exchange (__ATOMIC_RELEASE) */
	if (__atomic_load_n(&client->pool, __ATOMIC_ACQUIRE)) {
		assert(pool_size == client->pool_size);
		return 0;
	}

	pool = mmap(NULL, pool_size, PROT_READ, MAP_SHARED, client->fd, 0);
	if (pool == MAP_FAILED)
		return -errno;

	/* NULL is never mapped if we let the kernel choose; we rely on this */
	assert(pool != NULL);

	/* no reason to be atomic, but lets verify the semantics nonetheless */
	old_size = __atomic_exchange_n(&client->pool_size, pool_size,
				       __ATOMIC_RELEASE);
	assert(old_size == 0 || old_size == pool_size);

	old_pool = NULL;
	if (!__atomic_compare_exchange_n(&client->pool, &old_pool, pool, false,
					 __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
		munmap((void *)pool, pool_size);

	return 0;
}

_public_ int bus1_client_init(struct bus1_client *client, size_t pool_size)
{
	struct bus1_cmd_peer_init peer_init;
	size_t old_size;
	int r;

	peer_init.flags = 0;
	peer_init.pool_size = pool_size;

	static_assert(_IOC_SIZE(BUS1_CMD_PEER_INIT) == sizeof(peer_init),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_PEER_INIT, &peer_init);
	if (r < 0)
		return r;

	/* no reason to be atomic, but lets verify the semantics nonetheless */
	old_size = __atomic_exchange_n(&client->pool_size, pool_size,
				       __ATOMIC_RELEASE);
	assert(old_size == 0 || old_size == pool_size);

	return 0;
}

_public_ int bus1_client_clone(struct bus1_client *client,
			       uint64_t *handlep,
			       int *fdp,
			       size_t pool_size)
{
	struct bus1_cmd_peer_clone peer_clone;
	int r;

	peer_clone.flags = 0;
	peer_clone.pool_size = pool_size;
	peer_clone.handle = BUS1_HANDLE_INVALID;
	peer_clone.fd = (uint64_t)-1;

	static_assert(_IOC_SIZE(BUS1_CMD_PEER_CLONE) == sizeof(peer_clone),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_PEER_CLONE, &peer_clone);
	if (r < 0)
		return r;

	assert(peer_clone.fd != (uint64_t)-1);
	assert(peer_clone.handle != BUS1_HANDLE_INVALID);

	*handlep = peer_clone.handle;
	*fdp = peer_clone.fd;
	return 0;
}

_public_ int bus1_client_node_destroy(struct bus1_client *client,
				      uint64_t handle)
{
	static_assert(_IOC_SIZE(BUS1_CMD_NODE_DESTROY) == sizeof(handle),
		      "ioctl is called with invalid argument size");

	return bus1_client_ioctl(client, BUS1_CMD_NODE_DESTROY, &handle);
}

_public_ int bus1_client_handle_release(struct bus1_client *client,
					uint64_t handle)
{
	static_assert(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) == sizeof(handle),
		      "ioctl is called with invalid argument size");

	return bus1_client_ioctl(client, BUS1_CMD_HANDLE_RELEASE, &handle);
}

_public_ int bus1_client_slice_release(struct bus1_client *client,
				       uint64_t offset)
{
	static_assert(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) == sizeof(offset),
		      "ioctl is called with invalid argument size");

	return bus1_client_ioctl(client, BUS1_CMD_SLICE_RELEASE, &offset);
}

_public_ void *bus1_client_slice_from_offset(struct bus1_client *client,
					     uint64_t offset)
{
	if (!client->pool || offset >= client->pool_size)
		return NULL;

	return (uint8_t *)client->pool + offset;
}

_public_ uint64_t bus1_client_slice_to_offset(struct bus1_client *client,
					      const void *slice)
{
	if (_unlikely_(!client->pool || !client->pool_size || slice < client->pool))
		return BUS1_OFFSET_INVALID;
	if (_unlikely_((uint8_t *)slice >= (uint8_t *)client->pool + client->pool_size))
		return BUS1_OFFSET_INVALID;

	return (uint8_t *)slice - (uint8_t *)client->pool;
}

_public_ int bus1_client_send(struct bus1_client *client,
			      uint64_t *destinations, size_t n_destinations,
			      struct iovec *vecs, size_t n_vecs,
			      uint64_t *handles, size_t n_handles,
			      int *fds, size_t n_fds)
{
	struct bus1_cmd_send send = {
		.flags = n_destinations > 1 ? BUS1_SEND_FLAG_CONTINUE : 0,
		.ptr_destinations = (uint64_t)destinations,
		.n_destinations = n_destinations,
		.ptr_vecs = (uint64_t)vecs,
		.n_vecs = n_vecs,
		.ptr_handles = (uint64_t)handles,
		.n_handles = n_handles,
		.ptr_fds = (uint64_t)fds,
		.n_fds = n_fds,
	};
	int r;

	static_assert(_IOC_SIZE(BUS1_CMD_SEND) == sizeof(send),
		      "ioctl is called with invalid argument size");

	r = bus1_client_ioctl(client, BUS1_CMD_SEND, &send);
	if (r < 0)
		return r;

	return 0;
}
