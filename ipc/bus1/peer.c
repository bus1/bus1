/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <uapi/linux/bus1.h>
#include "domain.h"
#include "filesystem.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"

/**
 * bus1_peer_new() - create new peer
 *
 * XXX:
 *
 * Return: Pointer to new peer, or ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(struct bus1_domain *domain,
				struct bus1_cmd_connect *param)
{
	struct bus1_peer *peer;
	int r;

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	mutex_init(&peer->lock);
	peer->pool = BUS1_POOL_NULL;
	bus1_queue_init(&peer->queue);

	r = bus1_pool_create(&peer->pool, param->pool_size);
	if (r < 0)
		goto error;

	return peer;

error:
	bus1_peer_free(peer);
	return ERR_PTR(r);
}

/**
 * bus1_peer_free() - destroy peer
 * @peer:	peer to destroy, or NULL
 *
 * This destroys and deallocates a peer object, which was previously created
 * via bus1_peer_new(). The caller must make sure no-one else is accessing the
 * peer object at the same time.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	bus1_queue_destroy(&peer->queue);
	bus1_pool_destroy(&peer->pool);
	kfree(peer);

	return NULL;
}

/**
 * bus1_peer_ioctl() - handle peer ioctl
 * @peer:		peer to work on
 * @fs_domain:		parent domain
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on the passed peer @peer. The caller
 * must provide the parent domain of @peer as @fs_domain. It may be used for
 * other peer lookups.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl(struct bus1_peer *peer,
		    struct bus1_fs_domain *fs_domain,
		    unsigned int cmd,
		    unsigned long arg)
{
	int r;

	switch (cmd) {
	case BUS1_CMD_FREE:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_TRACK:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_UNTRACK:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_SEND:
		r = 0; /* XXX */
		break;
	case BUS1_CMD_RECV:
		r = 0; /* XXX */
		break;
	default:
		r = -ENOTTY;
		break;
	}

	return r;
}
