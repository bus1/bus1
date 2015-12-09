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
#include <linux/slab.h>
#include "peer.h"

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

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	return peer;
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

	kfree(peer);

	return NULL;
}
