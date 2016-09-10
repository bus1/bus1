/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
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
#include "bus1-peer.h"

struct bus1_peer {
	const uint8_t *pool;
	size_t pool_size;
	int fd;
};

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _likely_(_x) (__builtin_expect(!!(_x), 1))
#define _unlikely_(_x) (__builtin_expect(!!(_x), 0))

int bus1_peer_new_from_fd(struct bus1_peer **peerp, int fd)
{
	_cleanup_(bus1_peer_freep) struct bus1_peer *peer = NULL;

	assert(fd >= 0);

	peer = malloc(sizeof(*peer));
	if (!peer)
		return -ENOMEM;

	peer->fd = fd;
	peer->pool = NULL;
	/* XXX: remap the pool dynamically */
	peer->pool_size = BUS1_DEFAULT_POOL_SIZE;

	*peerp = peer;
	peer = NULL;
	return 0;
}

int bus1_peer_new_from_path(struct bus1_peer **peerp, const char *path)
{
	int r, fd;

	if (!path)
		path = "/dev/bus1";

	fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	r = bus1_peer_new_from_fd(peerp, fd);
	if (r < 0)
		close(fd);

	return r;
}

struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	if (peer->pool)
		munmap((void *)peer->pool, peer->pool_size);

	close(peer->fd);
	free(peer);

	return NULL;
}

int bus1_peer_get_fd(struct bus1_peer *peer)
{
	return peer ? peer->fd : -1;
}

size_t bus1_peer_get_pool_size(struct bus1_peer *peer)
{
	return peer ? peer->pool_size : 0;
}

const void *bus1_peer_get_pool(struct bus1_peer *peer)
{
	return peer ? peer->pool : NULL;
}

int bus1_peer_ioctl(struct bus1_peer *peer, unsigned int cmd, void *arg)
{
	int r;

	r = ioctl(peer->fd, cmd, arg);
	return r >= 0 ? r : -errno;
}

int bus1_peer_mmap(struct bus1_peer *peer)
{
	const void *pool, *old_pool;
	size_t pool_size;

	/*
	 * MMap the pool of @peer with size @pool_size. Note that this might
	 * be called in parallel on multiple threads. However, @pool_size is
	 * static so that is fine.
	 *
	 * We first acquire @pool and see whether it is set. If it is, we know
	 * we are already done so we simply bail out. If it is not set (i.e.,
	 * it equals NULL), we have to map it. We then first write the
	 * pool-size atomically on the peer. If we race anyone else, we don't
	 * care since everyone would write the same pool-size. Next, we write
	 * the mapping-pointer. We must do this atomically and verify that we
	 * replace the previous NULL. If we didn't replace it, we raced
	 * another mmap() so we unmap our temporary map and acquire theirs (via
	 * __ATOMIC_ACQUIRE on the failure path). If we successfully replaced
	 * it, we are in-sync and can return (but we must write it via
	 * __ATOMIC_RELEASE, to sync it with any racing __atomic_load()
	 * fast-path).
	 */

	/* fastpath: sync'ed with atomic exchange (__ATOMIC_RELEASE) */
	if (__atomic_load_n(&peer->pool, __ATOMIC_ACQUIRE)) {
		assert(pool_size == peer->pool_size);
		return 0;
	}

	pool = mmap(NULL, peer->pool_size, PROT_READ, MAP_SHARED,
		    peer->fd, 0);
	if (pool == MAP_FAILED)
		return -errno;

	/* NULL is never mapped if we let the kernel choose; we rely on this */
	assert(pool != NULL);

	old_pool = NULL;
	if (!__atomic_compare_exchange_n(&peer->pool, &old_pool, pool, false,
					 __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
		munmap((void *)pool, peer->pool_size);

	return 0;
}

int bus1_peer_disconnect(struct bus1_peer *peer)
{
	return bus1_peer_ioctl(peer, BUS1_CMD_PEER_DISCONNECT, NULL);
}

int bus1_peer_handle_transfer(struct bus1_peer *src,
			      struct bus1_peer *dst,
			      uint64_t *src_handlep,
			      uint64_t *dst_handlep)
{
	struct bus1_cmd_handle_transfer handle_transfer;
	int r;

	handle_transfer.flags = 0;
	handle_transfer.src_handle = *src_handlep;
	handle_transfer.dst_fd = dst->fd;
	handle_transfer.dst_handle = *dst_handlep;

	static_assert(_IOC_SIZE(BUS1_CMD_HANDLE_TRANSFER) ==
		      sizeof(handle_transfer),
		      "ioctl is called with invalid argument size");

	r = bus1_peer_ioctl(src, BUS1_CMD_HANDLE_TRANSFER, &handle_transfer);
	if (r < 0)
		return r;

	assert(handle_transfer.src_handle != BUS1_HANDLE_INVALID);
	assert(handle_transfer.dst_handle != BUS1_HANDLE_INVALID);

	*src_handlep = handle_transfer.src_handle;
	*dst_handlep = handle_transfer.dst_handle;
	return 0;
}

int bus1_peer_handle_release(struct bus1_peer *peer,
			     uint64_t handle)
{
	static_assert(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) == sizeof(handle),
		      "ioctl is called with invalid argument size");

	return bus1_peer_ioctl(peer, BUS1_CMD_HANDLE_RELEASE, &handle);
}

int bus1_peer_slice_release(struct bus1_peer *peer,
			    uint64_t offset)
{
	static_assert(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) == sizeof(offset),
		      "ioctl is called with invalid argument size");

	return bus1_peer_ioctl(peer, BUS1_CMD_SLICE_RELEASE, &offset);
}

const void *bus1_peer_slice_from_offset(struct bus1_peer *peer,
					uint64_t offset)
{
	if (_unlikely_(!peer->pool || offset >= peer->pool_size))
		return NULL;

	return peer->pool + offset;
}

uint64_t bus1_peer_slice_to_offset(struct bus1_peer *peer, const void *slice)
{
	if (_unlikely_(!peer->pool ||
		       !peer->pool_size ||
		       (uint8_t *)slice < peer->pool ||
		       (uint8_t *)slice >= peer->pool + peer->pool_size))
		return BUS1_OFFSET_INVALID;

	return (uint8_t *)slice - peer->pool;
}
