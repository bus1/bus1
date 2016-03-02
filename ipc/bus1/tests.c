/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <uapi/linux/bus1.h>
#include "peer.h"
#include "tests.h"

static void bus1_test_user(void)
{
	struct bus1_user *user;
	kuid_t uid = KUIDT_INIT(0);

	user = bus1_user_ref_by_uid(uid);
	WARN_ON(!user);

	WARN_ON(bus1_user_unref(user));
}

static void bus1_test_pool(void)
{
	struct bus1_peer_info peer = {};
	struct bus1_pool *pool = &peer.pool;

	/* make lockdep happy */
	mutex_init(&peer.lock);
	mutex_lock(&peer.lock);

	WARN_ON(bus1_pool_create_for_peer(pool, &peer, BUS1_POOL_SIZE_MAX + 1) !=
								-EMSGSIZE);
	WARN_ON(bus1_pool_create_for_peer(pool, &peer, 0) != -EMSGSIZE);
	WARN_ON(bus1_pool_create_for_peer(pool, &peer, PAGE_SIZE) < 0);
	bus1_pool_destroy(pool);

	mutex_unlock(&peer.lock);
}

static void bus1_test_peer(void)
{
	struct bus1_peer *peer;
	struct bus1_cmd_connect param = {};
	kuid_t uid = KUIDT_INIT(0);

	peer = bus1_peer_new();
	WARN_ON(!peer);
	WARN_ON(!bus1_active_is_new(&peer->active));
	WARN_ON(peer->info);

	/* test invalid modes */
	param.flags = ~(BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR |
			BUS1_CONNECT_FLAG_QUERY | BUS1_CONNECT_FLAG_RESET);
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR |
		      BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_MONITOR | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_MONITOR | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.flags = 0;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);

	/* test invalid operations on unconnected peer */
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ENOTCONN);
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ENOTCONN);

	/* test new client */
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.pool_size = 1;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.pool_size = PAGE_SIZE;
	WARN_ON(bus1_peer_connect(peer, uid, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EISCONN);

	/* test query */
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.pool_size = 0;
	WARN_ON(bus1_peer_connect(peer, uid, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);

	/* test reset */
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -EINVAL);
	param.pool_size = 0;
	WARN_ON(bus1_peer_connect(peer, uid, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);

	/* test disconnect */
	WARN_ON(bus1_peer_disconnect(peer) < 0);
	WARN_ON(bus1_peer_acquire(peer));
	WARN_ON(peer->info);

	/* test invalid operations on disconnected peer */
	WARN_ON(bus1_peer_disconnect(peer) != -ESHUTDOWN);
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ESHUTDOWN);
	param.pool_size = 0;
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ESHUTDOWN);
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ESHUTDOWN);

	WARN_ON(bus1_peer_free(peer));

	/* disconnect before connect */
	peer = bus1_peer_new();
	WARN_ON(!peer);
	WARN_ON(bus1_peer_disconnect(peer) < 0);
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	param.pool_size = PAGE_SIZE;
	WARN_ON(bus1_peer_connect(peer, uid, &param) != -ESHUTDOWN);
	WARN_ON(bus1_peer_free(peer));
}

void bus1_tests_run(void)
{
	bus1_test_user();
	bus1_test_pool();
	bus1_test_peer();
}
