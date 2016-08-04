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
	WARN_ON(atomic_read(&user1->n_slices) !=
					atomic_read(&user1->max_slices));
	WARN_ON(atomic_read(&user1->n_handles) !=
					atomic_read(&user1->max_handles));
	WARN_ON(atomic_read(&user1->n_inflight_bytes) !=
					atomic_read(&user1->max_bytes));
	WARN_ON(atomic_read(&user1->n_inflight_fds) !=
					atomic_read(&user1->max_fds));

	/* create a different user */
	user2 = bus1_user_ref_by_uid(uid2);
	WARN_ON(!user2);
	WARN_ON(user1 == user2);
	WARN_ON(__kuid_val(user2->uid) != 2);
	WARN_ON(user2->id != 1);
	WARN_ON(atomic_read(&user2->n_slices) !=
					atomic_read(&user2->max_slices));
	WARN_ON(atomic_read(&user2->n_handles) !=
					atomic_read(&user2->max_handles));
	WARN_ON(atomic_read(&user2->n_inflight_bytes) !=
					atomic_read(&user2->max_bytes));
	WARN_ON(atomic_read(&user2->n_inflight_fds) !=
					atomic_read(&user2->max_fds));

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
	peer.user = owner;
	mutex_lock(&peer.lock);
	bus1_pool_create_for_peer(&peer);

	/* charge nothing: allocates the user stats, charge one message */
	r = bus1_user_quota_charge(&peer, user1, 0, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 1);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_bytes) !=
				atomic_read(&owner->max_bytes));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 1);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	bus1_user_quota_discharge(&peer, user1, 0, 0, 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices));
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_bytes) !=
				atomic_read(&owner->max_bytes));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	/* exceed the quota: nothing happens */
	r = bus1_user_quota_charge(&peer, user1, -1, 0, 0);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices));
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_bytes) !=
				atomic_read(&owner->max_bytes));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1, 0, -1, 0);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices));
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1, 0, 0, -1);
	WARN_ON(r != -EDQUOT);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices));
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	/* verify the limits: size */
	r = bus1_user_quota_charge(&peer, user1,
				   atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 1);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 1);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes !=
					atomic_read(&owner->max_bytes) / 4);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1,
				   atomic_read(&owner->max_bytes) / 4 + 1,
				   0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2,
				   atomic_read(&owner->max_bytes) / 4 + 1,
				   0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 2);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_slices != 1);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_bytes !=
					atomic_read(&owner->max_bytes) / 4 + 1);
	WARN_ON(peer.quota.stats[1].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1,
				   atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(r != -EDQUOT);

	bus1_user_quota_discharge(&peer, user2,
				  atomic_read(&owner->max_bytes) / 4 + 1,
				  0, 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 1);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_slices != 0);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_bytes != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1,
				   atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 2);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 1);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 2);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes !=
					atomic_read(&owner->max_bytes) / 2);
	WARN_ON(peer.quota.stats[0].n_fds != 0);

	r = bus1_user_quota_charge(&peer, user1,
				   atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2,
				   atomic_read(&owner->max_bytes) / 4 + 1,
				   0, 0);
	WARN_ON(r != -EDQUOT);

	r = bus1_user_quota_charge(&peer, user2,
				   atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(r < 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices) - 3);
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[1].n_slices != 1);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_bytes !=
					atomic_read(&owner->max_bytes) / 4);
	WARN_ON(peer.quota.stats[1].n_fds != 0);

	bus1_user_quota_discharge(&peer, user1,
				  atomic_read(&owner->max_bytes) / 4, 0, 0);
	bus1_user_quota_discharge(&peer, user1,
				  atomic_read(&owner->max_bytes) / 4, 0, 0);
	bus1_user_quota_discharge(&peer, user2,
				  atomic_read(&owner->max_bytes) / 4, 0, 0);
	WARN_ON(atomic_read(&owner->n_slices) !=
				atomic_read(&owner->max_slices));
	WARN_ON(atomic_read(&owner->n_handles) !=
				atomic_read(&owner->max_handles));
	WARN_ON(atomic_read(&owner->n_inflight_fds) !=
				atomic_read(&owner->max_fds));
	WARN_ON(peer.quota.n_stats < 2);
	WARN_ON(peer.quota.stats == NULL);
	WARN_ON(peer.quota.stats[0].n_slices != 0);
	WARN_ON(peer.quota.stats[0].n_handles != 0);
	WARN_ON(peer.quota.stats[0].n_bytes != 0);
	WARN_ON(peer.quota.stats[0].n_fds != 0);
	WARN_ON(peer.quota.stats[1].n_slices != 0);
	WARN_ON(peer.quota.stats[1].n_handles != 0);
	WARN_ON(peer.quota.stats[1].n_bytes != 0);
	WARN_ON(peer.quota.stats[1].n_fds != 0);

	bus1_pool_destroy(&peer.pool);
	mutex_unlock(&peer.lock);
	bus1_user_quota_destroy(&peer.quota);
	WARN_ON(bus1_user_unref(user1));
	WARN_ON(bus1_user_unref(user2));
	WARN_ON(bus1_user_unref(owner));
}

void bus1_tests_run(void)
{
	pr_info("run selftests..\n");
	bus1_test_user();
	bus1_test_quota();
}
