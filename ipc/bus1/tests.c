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
#include "main.h"
#include "peer.h"
#include "tests.h"

static void bus1_test_user(void)
{
	struct bus1_user *user1, *user2;
	kuid_t uid1 = KUIDT_INIT(1), uid2 = KUIDT_INIT(2);

	/* drop the NULL user */
	bus1_user_unref(NULL);

	/* create a user */
	user1 = bus1_user_ref_by_uid(uid1);
	WARN_ON(!user1);
	WARN_ON(__kuid_val(user1->uid) != 1);
	WARN_ON(user1->id != 0);
	WARN_ON(atomic_read(&user1->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&user1->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&user1->n_fds) != BUS1_FDS_MAX);
	WARN_ON(atomic_read(&user1->max_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&user1->max_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&user1->max_fds) != BUS1_FDS_MAX);

	/* create a different user */
	user2 = bus1_user_ref_by_uid(uid2);
	WARN_ON(!user2);
	WARN_ON(user1 == user2);
	WARN_ON(__kuid_val(user2->uid) != 2);
	WARN_ON(user2->id != 1);
	WARN_ON(atomic_read(&user2->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&user2->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&user2->n_fds) != BUS1_FDS_MAX);
	WARN_ON(atomic_read(&user2->max_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&user2->max_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&user2->max_fds) != BUS1_FDS_MAX);

	/* drop the second user */
	user2 = bus1_user_unref(user2);
	WARN_ON(user2);

	/* take another ref on the first user */
	user2 = bus1_user_ref(user1);
	WARN_ON(user1 != user2);

	/* drop the ref again */
	user2 = bus1_user_unref(user2);
	WARN_ON(user2);

	/* look up the first user again by uid */
	user2 = bus1_user_ref_by_uid(uid1);
	WARN_ON(user1 != user2);

	WARN_ON(bus1_user_unref(user1));
	WARN_ON(bus1_user_unref(user2));
}

static void bus1_test_quota(void)
{
	struct bus1_peer_info peer = {};
	struct bus1_user *owner, *user1, *user2;
	int r;

	/* init and destroy */
	bus1_user_quota_destroy(NULL);

	bus1_user_quota_init(&peer.quota);
	WARN_ON(peer.quota.n_stats != 0);
	WARN_ON(peer.quota.stats != NULL);

	bus1_user_quota_destroy(&peer.quota);

	/* charge and discharge */

	user1 = bus1_user_ref_by_uid(KUIDT_INIT(1));
	WARN_ON(!user1);
	user2 = bus1_user_ref_by_uid(KUIDT_INIT(2));
	WARN_ON(!user2);
	owner = bus1_user_ref_by_uid(KUIDT_INIT(3));
	WARN_ON(!owner);

	bus1_user_quota_init(&peer.quota);
	WARN_ON(peer.quota.stats != NULL);
	WARN_ON(peer.quota.n_stats != 0);

	mutex_init(&peer.lock);
	peer.n_messages = BUS1_MESSAGES_MAX;
	peer.n_handles = BUS1_HANDLES_MAX;
	peer.n_fds = 1024;
	peer.n_bytes = 1024;
	peer.user = owner;
	mutex_lock(&peer.lock);
	bus1_pool_create_for_peer(&peer, 1024);

	/* charge nothing: allocates the user stats, charge one message */
	r = bus1_user_quota_charge(&peer, user1, 0, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 1);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 1);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 1);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	bus1_user_quota_discharge(&peer, user1, 0, 0, 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	/* exceed the quota: nothing happens */
	r = bus1_user_quota_charge(&peer, user1, -1, 0, 0);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 0, -1, 0);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 0, 0, -1);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	/* verify the limits: size */
	r = bus1_user_quota_charge(&peer, user1, 1024 / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 1);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 1024 / 4);
	WARN_ON(peer.quota.stats[0].n_messages != 1);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024 / 4 * 3);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 1);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 1024 / 4 + 1, 0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2, 1024 / 4 + 1, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 2);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_bytes != 1024 / 4 + 1);
	WARN_ON(peer.quota.stats[1].n_messages != 1);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024 / 2 - 1);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 2);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 1024 / 4, 0, 0);
	WARN_ON(r != -EDQUOT);

	bus1_user_quota_discharge(&peer, user2, 1024 / 4 + 1, 0, 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 1);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_bytes != 0);
	WARN_ON(peer.quota.stats[1].n_messages != 0);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024 / 4 * 3);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 1);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 1024 / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 2);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 1024 / 2);
	WARN_ON(peer.quota.stats[0].n_messages != 2);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024 / 2);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 2);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	r = bus1_user_quota_charge(&peer, user1, 1024 / 4, 0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2, 1024 / 4 + 1, 0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2, 1024 / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX - 3);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_bytes != 1024 / 4);
	WARN_ON(peer.quota.stats[1].n_messages != 1);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024 / 4);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX - 3);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	bus1_user_quota_discharge(&peer, user1, 1024 / 4, 0, 0);
	bus1_user_quota_discharge(&peer, user1, 1024 / 4, 0, 0);
	bus1_user_quota_discharge(&peer, user2, 1024 / 4, 0, 0);
	WARN_ON(atomic_read(&owner->n_messages) != BUS1_MESSAGES_MAX);
	WARN_ON(atomic_read(&owner->n_handles) != BUS1_HANDLES_MAX);
	WARN_ON(atomic_read(&owner->n_fds) != BUS1_FDS_MAX);
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_messages != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.quota.stats[1].n_bytes != 0);
	WARN_ON(peer.quota.stats[1].n_messages != 0);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);
	WARN_ON(peer.n_bytes != 1024);
	WARN_ON(peer.n_messages != BUS1_MESSAGES_MAX);
	WARN_ON(peer.n_handles != BUS1_HANDLES_MAX);
	WARN_ON(peer.n_fds != 1024);

	bus1_pool_destroy(&peer.pool);
	mutex_unlock(&peer.lock);
	bus1_user_quota_destroy(&peer.quota);
	WARN_ON(bus1_user_unref(user1));
	WARN_ON(bus1_user_unref(user2));
	WARN_ON(bus1_user_unref(owner));
}

static void bus1_test_pool(void)
{
	struct bus1_peer_info peer = {};
	struct bus1_pool *pool = &peer.pool;
	struct bus1_pool_slice *slice1, *slice2, *slice3;
	size_t offset, size, n_slices, slices_size;

	/* make lockdep happy */
	mutex_init(&peer.lock);
	mutex_lock(&peer.lock);

	WARN_ON(bus1_pool_create_for_peer(&peer, BUS1_POOL_SIZE_MAX + 1)
		!= -EMSGSIZE);
	WARN_ON(bus1_pool_create_for_peer(&peer, 0) != -EMSGSIZE);
	WARN_ON(bus1_pool_create_for_peer(&peer, PAGE_SIZE - 8) < 0);

	WARN_ON(bus1_pool_alloc(pool, 0) != ERR_PTR(-EMSGSIZE));
	WARN_ON(bus1_pool_alloc(pool, BUS1_POOL_SLICE_SIZE_MAX + 1) !=
		ERR_PTR(-EMSGSIZE));
	WARN_ON(bus1_pool_alloc(pool, PAGE_SIZE) != ERR_PTR(-EXFULL));

	/* split the pool in four parts, the first three of equal size and
	 * the reminder the same size - 1 */
	slice1 = bus1_pool_alloc(pool, PAGE_SIZE / 4);
	slice2 = bus1_pool_alloc(pool, PAGE_SIZE / 4);
	slice3 = bus1_pool_alloc(pool, PAGE_SIZE / 4);
	WARN_ON(IS_ERR(slice1) || IS_ERR(slice2) || IS_ERR(slice3));
	/* there is not space for a fourth */
	WARN_ON(bus1_pool_alloc(pool, PAGE_SIZE / 4) != ERR_PTR(-EXFULL));

	/* drop the first slice */
	slice1 = bus1_pool_release_kernel(pool, slice1);
	WARN_ON(slice1);
	/* there is enough space in the pool, but the slices are not
	 * adjacent for a bigger slice */
	WARN_ON(bus1_pool_alloc(pool, PAGE_SIZE / 3) !=
		ERR_PTR(-EXFULL));
	/* there is space to add back a same sized slice though */
	slice1 = bus1_pool_alloc(pool, PAGE_SIZE / 4);
	WARN_ON(IS_ERR(slice1));
	/* drop the last slice instead */
	slice3 = bus1_pool_release_kernel(pool, slice3);
	WARN_ON(slice3);
	/* now there is space for the bigger slice */
	slice3 = bus1_pool_alloc(pool, PAGE_SIZE / 3);
	WARN_ON(IS_ERR(slice3));

	/* test publish and release */
	/* can't release a non-existet slice */
	WARN_ON(bus1_pool_release_user(pool, 1, NULL) != -ENXIO);
	/* can't user-release an unpublished slice */
	WARN_ON(bus1_pool_release_user(pool, PAGE_SIZE / 4, NULL) != -ENXIO);
	/* verify that publish does the righ thing */
	bus1_pool_publish(pool, slice2);
	WARN_ON(slice2->offset != PAGE_SIZE / 4);
	WARN_ON(slice2->size != PAGE_SIZE / 4);
	/* release the slice again */
	WARN_ON(bus1_pool_release_user(pool, slice2->offset, &size) < 0);
	WARN_ON(size != PAGE_SIZE / 4);
	/* can't release a slice that has already been released */
	WARN_ON(bus1_pool_release_user(pool, slice2->offset, NULL) != -ENXIO);
	/* publish again */
	bus1_pool_publish(pool, slice2);
	offset = slice2->offset;
	/* release the kernel ref */
	slice2 = bus1_pool_release_kernel(pool, slice2);
	/* verify that the slice is still busy by trying to reuse the space */
	WARN_ON(bus1_pool_alloc(pool, PAGE_SIZE / 4) != ERR_PTR(-EXFULL));
	/* now also release the user ref */
	WARN_ON(bus1_pool_release_user(pool, offset, &size) < 0);
	WARN_ON(size != PAGE_SIZE / 4);
	/* verify that the slice was now released and the space can be reused */
	slice2 = bus1_pool_alloc(pool, PAGE_SIZE / 4);
	WARN_ON(IS_ERR(slice2));
	/* publish all slices */
	bus1_pool_publish(pool, slice1);
	WARN_ON(slice1->offset != 0);
	WARN_ON(slice1->size != PAGE_SIZE / 4);
	bus1_pool_publish(pool, slice2);
	WARN_ON(slice2->offset != PAGE_SIZE / 4);
	WARN_ON(slice2->size != PAGE_SIZE / 4);
	bus1_pool_publish(pool, slice3);
	WARN_ON(slice3->offset != PAGE_SIZE / 2);
	WARN_ON(slice3->size != ALIGN(PAGE_SIZE / 3, 8));
	/* flush user references */
	bus1_pool_flush(pool, &n_slices, &slices_size);
	WARN_ON(n_slices != 3);
	WARN_ON(slices_size != PAGE_SIZE / 2 + ALIGN(PAGE_SIZE / 3, 8));

	/* XXX: test writing of iovecs and kvecs */

	/* drop all slices before destorying pool */
	slice1 = bus1_pool_release_kernel(pool, slice1);
	slice2 = bus1_pool_release_kernel(pool, slice2);
	slice3 = bus1_pool_release_kernel(pool, slice3);

	bus1_pool_destroy(pool);
	mutex_unlock(&peer.lock);
}

static void bus1_test_peer(void)
{
#if 0
	struct bus1_peer *peer;
	struct bus1_cmd_connect param = {};
	const struct cred *cred;
	struct pid_namespace *pid_ns;

	cred = current_cred();
	pid_ns = task_active_pid_ns(current);

	peer = bus1_peer_new();
	WARN_ON(!peer);
	WARN_ON(!bus1_active_is_new(&peer->active));
	WARN_ON(peer->info);

	/* test invalid modes */
	param.flags = ~(BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR |
			BUS1_CONNECT_FLAG_QUERY | BUS1_CONNECT_FLAG_RESET);
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR |
		      BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_MONITOR;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_MONITOR | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = BUS1_CONNECT_FLAG_MONITOR | BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.flags = 0;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);

	/* test invalid operations on unconnected peer */
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ENOTCONN);
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ENOTCONN);

	/* test new client */
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.pool_size = 1;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.pool_size = PAGE_SIZE;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EISCONN);

	/* test query */
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.pool_size = 0;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);

	/* test reset */
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -EINVAL);
	param.pool_size = 0;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) < 0);
	WARN_ON(param.pool_size != PAGE_SIZE);

	/* test disconnect */
	WARN_ON(bus1_peer_disconnect(peer) < 0);
	WARN_ON(bus1_peer_acquire(peer));
	WARN_ON(peer->info);

	/* test invalid operations on disconnected peer */
	WARN_ON(bus1_peer_disconnect(peer) != -ESHUTDOWN);
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ESHUTDOWN);
	param.pool_size = 0;
	param.flags = BUS1_CONNECT_FLAG_QUERY;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ESHUTDOWN);
	param.flags = BUS1_CONNECT_FLAG_RESET;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ESHUTDOWN);

	WARN_ON(bus1_peer_free(peer));

	/* disconnect before connect */
	peer = bus1_peer_new();
	WARN_ON(!peer);
	WARN_ON(bus1_peer_disconnect(peer) < 0);
	param.flags = BUS1_CONNECT_FLAG_CLIENT;
	param.pool_size = PAGE_SIZE;
	WARN_ON(bus1_peer_connect(peer, cred, pid_ns, &param) != -ESHUTDOWN);
	WARN_ON(bus1_peer_free(peer));
#endif
}

void bus1_tests_run(void)
{
	pr_info("run selftests..\n");
	bus1_test_user();
	bus1_test_quota();
	bus1_test_pool();
	bus1_test_peer();
}
