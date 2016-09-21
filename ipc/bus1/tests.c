/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "main.h"
#include "peer.h"
#include "tests.h"

static void active_cleanup(struct bus1_active *active, void *userdata)
{
	bool *clean = userdata;

	WARN_ON(*clean);
	*clean = true;
}

static void bus1_test_active(void)
{
	struct bus1_active active;
	bool clean = false;

	/* simple api tests only, only single-threaded so no waitq tests */

	bus1_active_init(&active);

	WARN_ON(!bus1_active_is_new(&active));
	WARN_ON(bus1_active_is_active(&active));
	WARN_ON(bus1_active_is_deactivated(&active));
	WARN_ON(bus1_active_is_drained(&active));

	WARN_ON(bus1_active_acquire(&active));
	WARN_ON(!bus1_active_activate(&active));
	WARN_ON(bus1_active_activate(&active));
	WARN_ON(!bus1_active_acquire(&active));

	WARN_ON(bus1_active_is_new(&active));
	WARN_ON(!bus1_active_is_active(&active));
	WARN_ON(bus1_active_is_deactivated(&active));
	WARN_ON(bus1_active_is_drained(&active));

	WARN_ON(!bus1_active_deactivate(&active));
	WARN_ON(bus1_active_deactivate(&active));
	WARN_ON(bus1_active_activate(&active));

	WARN_ON(bus1_active_acquire(&active));

	WARN_ON(bus1_active_is_new(&active));
	WARN_ON(bus1_active_is_active(&active));
	WARN_ON(!bus1_active_is_deactivated(&active));
	WARN_ON(bus1_active_is_drained(&active));

	WARN_ON(bus1_active_release(&active, NULL));

	bus1_active_drain(&active, NULL);

	WARN_ON(bus1_active_is_new(&active));
	WARN_ON(bus1_active_is_active(&active));
	WARN_ON(!bus1_active_is_deactivated(&active));
	WARN_ON(!bus1_active_is_drained(&active));

	WARN_ON(!bus1_active_cleanup(&active, NULL, active_cleanup, &clean));
	WARN_ON(bus1_active_cleanup(&active, NULL, active_cleanup, &clean));
	WARN_ON(!clean);

	bus1_active_destroy(&active);
}

static void bus1_test_pool(void)
{
	struct bus1_pool pool = BUS1_POOL_NULL;
	struct bus1_pool_slice *slice;
	char *payload = "PAYLOAD";
	struct iovec vec = {
		.iov_base = payload,
		.iov_len = strlen(payload),
	};
	struct kvec kvec = {
		.iov_base = payload,
		.iov_len = strlen(payload),
	};
	size_t n_slices;

	bus1_pool_destroy(&pool);
	WARN_ON(bus1_pool_create(&pool) < 0);

	slice = bus1_pool_alloc(&pool, 0);
	WARN_ON(PTR_ERR(slice) != -EMSGSIZE);
	slice = bus1_pool_alloc(&pool, -1);
	WARN_ON(PTR_ERR(slice) != -EMSGSIZE);
	slice = bus1_pool_alloc(&pool, 1024);
	WARN_ON(IS_ERR_OR_NULL(slice));
	bus1_pool_release_kernel(&pool, slice);
	slice = bus1_pool_alloc(&pool, 1024);
	WARN_ON(IS_ERR_OR_NULL(slice));
	WARN_ON(bus1_pool_release_user(&pool, slice->offset, &n_slices)
		>= 0);
	bus1_pool_publish(&pool, slice);
	WARN_ON(bus1_pool_release_user(&pool, slice->offset + 1, &n_slices)
		>= 0);
	WARN_ON(bus1_pool_release_user(&pool, slice->offset, &n_slices) < 0);
	WARN_ON(n_slices != 0);
	bus1_pool_release_kernel(&pool, slice);

	slice = bus1_pool_alloc(&pool, 1024);
	WARN_ON(IS_ERR_OR_NULL(slice));

	WARN_ON(bus1_pool_write_iovec(&pool, slice, 0, &vec, 1, vec.iov_len)
		< 0);
	WARN_ON(bus1_pool_write_kvec(&pool, slice, 0, &kvec, 1, kvec.iov_len)
		< 0);
	bus1_pool_publish(&pool, slice);
	bus1_pool_release_kernel(&pool, slice);
	WARN_ON(bus1_pool_release_user(&pool, slice->offset, &n_slices) < 0);
	WARN_ON(n_slices != 1);

	bus1_pool_destroy(&pool);
}

static void bus1_test_queue(void)
{
	wait_queue_head_t waitq;
	struct bus1_queue q1, q2, qa, qb;
	struct bus1_queue_node n1a, n1b, n2a, n2b;
	u64 ts1 = 0, ts2 = 0;
	bool has_continue;

	init_waitqueue_head(&waitq);

	bus1_queue_init(&q1, &waitq);
	bus1_queue_init(&q2, &waitq);
	bus1_queue_init(&qa, &waitq);
	bus1_queue_init(&qb, &waitq);

	/* set type to 0 and sender stamp to numbers to make order obvious */
	bus1_queue_node_init(&n1a, 0, 1);
	bus1_queue_node_init(&n1b, 0, 1);
	bus1_queue_node_init(&n2a, 0, 2);
	bus1_queue_node_init(&n2b, 0, 2);

	/* arbitrarily initialize the clocks */
	WARN_ON(bus1_queue_sync(&q1, 2) != 2);
	WARN_ON(bus1_queue_sync(&q2, 4) != 4);
	WARN_ON(bus1_queue_sync(&qa, 6) != 6);
	WARN_ON(bus1_queue_sync(&qb, 8) != 8);

	/* 'racing' staging of nodes */
	ts2 = bus1_queue_stage(&qa, &n2a, ts2);
	ts1 = bus1_queue_stage(&qa, &n1a, ts1);
	ts2 = bus1_queue_stage(&qb, &n2b, ts2);
	ts1 = bus1_queue_stage(&qb, &n1b, ts1);

	/* obtain final timestamps from source queues */
	ts1 = bus1_queue_sync(&q1, ts1);
	ts1 = bus1_queue_tick(&q1);
	ts2 = bus1_queue_sync(&q2, ts2);
	ts2 = bus1_queue_tick(&q2);

	/* 'racing' sync clocks on destination queues */
	bus1_queue_sync(&qa, ts2);
	bus1_queue_sync(&qa, ts1);
	bus1_queue_sync(&qb, ts1);
	bus1_queue_sync(&qb, ts2);

	/* 'racing' commit the entries */
	WARN_ON(!bus1_queue_commit_staged(&qa, &n1a, ts1));
	WARN_ON(!bus1_queue_commit_staged(&qb, &n1b, ts1));
	WARN_ON(!bus1_queue_commit_staged(&qb, &n2b, ts2));
	WARN_ON(!bus1_queue_commit_staged(&qa, &n2a, ts2));

	/* dequeue queue a */
	WARN_ON(bus1_queue_peek(&qa, &has_continue) != &n1a);
	WARN_ON(has_continue);
	WARN_ON(!bus1_queue_remove(&qa, &n1a));
	WARN_ON(bus1_queue_peek(&qa, &has_continue) != &n2a);
	WARN_ON(has_continue);
	WARN_ON(!bus1_queue_remove(&qa, &n2a));

	/* dequeue queue b */
	WARN_ON(bus1_queue_peek(&qb, &has_continue) != &n1b);
	WARN_ON(has_continue);
	WARN_ON(!bus1_queue_remove(&qb, &n1b));
	WARN_ON(bus1_queue_peek(&qb, &has_continue) != &n2b);
	WARN_ON(has_continue);
	WARN_ON(!bus1_queue_remove(&qb, &n2b));

	bus1_queue_destroy(&q1);
	bus1_queue_destroy(&q2);
	bus1_queue_destroy(&qa);
	bus1_queue_destroy(&qb);
}

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
	struct bus1_peer peer = {};
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
	bus1_pool_create(&peer.data.pool);

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

	bus1_pool_destroy(&peer.data.pool);
	mutex_unlock(&peer.lock);
	bus1_user_quota_destroy(&peer.quota);
	WARN_ON(bus1_user_unref(user1));
	WARN_ON(bus1_user_unref(user2));
	WARN_ON(bus1_user_unref(owner));
}

void bus1_tests_run(void)
{
	pr_info("run selftests..\n");
	bus1_test_active();
	bus1_test_pool();
	bus1_test_queue();
	bus1_test_user();
	bus1_test_quota();
}
