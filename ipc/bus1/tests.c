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
#include <linux/uio.h>
#include "handle.h"
#include "peer.h"
#include "tests.h"
#include "util/active.h"
#include "util/flist.h"
#include "util/pool.h"
#include "util/queue.h"

static void bus1_test_flist(void)
{
	struct bus1_flist *e, *list;
	size_t i, j, z, n;

	WARN_ON(bus1_flist_free(NULL, 0));
	WARN_ON(bus1_flist_new(0, GFP_TEMPORARY));

	/*
	 * Allocate small list, initialize all entries via normal iteration,
	 * then validate them via batch iteration.
	 */
	n = 8;
	list = bus1_flist_new(n, GFP_TEMPORARY);
	WARN_ON(!list);

	for (i = 0, e = list; i < n; e = bus1_flist_next(e, &i))
		e->ptr = (void *)(unsigned long)i;

	i = 0;
	while ((z = bus1_flist_walk(list, n, &e, &i)) > 0) {
		WARN_ON(z > BUS1_FLIST_BATCH);
		for (j = 0; j < z; ++j)
			WARN_ON(e[j].ptr != (void *)(unsigned long)(i - z + j));
	}

	bus1_flist_free(list, n);

	/*
	 * Same as above but this time with a huge array, bigger than the batch
	 * size of flists.
	 */
	n = BUS1_FLIST_BATCH * 8;
	list = bus1_flist_new(n, GFP_TEMPORARY);
	WARN_ON(!list);

	for (i = 0, e = list; i < n; e = bus1_flist_next(e, &i))
		e->ptr = (void *)(unsigned long)i;

	i = 0;
	while ((z = bus1_flist_walk(list, n, &e, &i)) > 0) {
		WARN_ON(z > BUS1_FLIST_BATCH);
		for (j = 0; j < z; ++j)
			WARN_ON(e[j].ptr != (void *)(unsigned long)(i - z + j));
	}

	bus1_flist_free(list, n);
}

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

	bus1_active_deinit(&active);
}

static void bus1_test_pool(void)
{
	struct bus1_pool pool = BUS1_POOL_NULL;
	struct bus1_pool_slice slice;
	char *payload = "PAYLOAD";
	struct iovec vec = {
		.iov_base = payload,
		.iov_len = strlen(payload),
	};
	struct kvec kvec = {
		.iov_base = payload,
		.iov_len = strlen(payload),
	};
	int r;

	bus1_pool_deinit(&pool);
	WARN_ON(bus1_pool_init(&pool, "test") < 0);
	bus1_pool_slice_init(&slice);

	r = bus1_pool_alloc(&pool, &slice, 0);
	WARN_ON(r != -EMSGSIZE);
	r = bus1_pool_alloc(&pool, &slice, -1);
	WARN_ON(r != -EMSGSIZE);
	r = bus1_pool_alloc(&pool, &slice, 1024);
	WARN_ON(r < 0);
	bus1_pool_publish(&slice);
	bus1_pool_unpublish(&slice);
	r = bus1_pool_dealloc(&pool, &slice);
	WARN_ON(r < 0);

	r = bus1_pool_alloc(&pool, &slice, 1024);
	WARN_ON(r < 0);
	r = bus1_pool_write_iovec(&pool, &slice, 0, &vec, 1, vec.iov_len);
	WARN_ON(r < 0);
	r = bus1_pool_write_kvec(&pool, &slice, 0, &kvec, 1, kvec.iov_len);
	WARN_ON(r < 0);
	bus1_pool_publish(&slice);
	bus1_pool_unpublish(&slice);
	r = bus1_pool_dealloc(&pool, &slice);
	WARN_ON(r < 0);

	bus1_pool_deinit(&pool);
}

static void bus1_test_queue(void)
{
	struct bus1_queue q1, q2, qa, qb;
	struct bus1_queue_node n1a, n1b, n2a, n2b;
	u64 ts1 = 0, ts2 = 0;
	bool has_continue;

	bus1_queue_init(&q1);
	bus1_queue_init(&q2);
	bus1_queue_init(&qa);
	bus1_queue_init(&qb);

	/* set type to 0 and sender group to numbers to make order obvious */
	bus1_queue_node_init(&n1a, 0);
	n1a.group = (void*)1;
	bus1_queue_node_init(&n1b, 0);
	n1b.group = (void*)1;
	bus1_queue_node_init(&n2a, 0);
	n2a.group = (void*)2;
	bus1_queue_node_init(&n2b, 0);
	n2b.group = (void*)2;

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
	bus1_queue_commit_staged(&qa, NULL, &n1a, ts1);
	bus1_queue_commit_staged(&qb, NULL, &n1b, ts1);
	bus1_queue_commit_staged(&qb, NULL, &n2b, ts2);
	bus1_queue_commit_staged(&qa, NULL, &n2a, ts2);

	/* dequeue queue a */
	WARN_ON(bus1_queue_peek(&qa, &has_continue) != &n1a);
	WARN_ON(has_continue);
	bus1_queue_remove(&qa, NULL, &n1a);
	WARN_ON(bus1_queue_peek(&qa, &has_continue) != &n2a);
	WARN_ON(has_continue);
	bus1_queue_remove(&qa, NULL, &n2a);

	/* dequeue queue b */
	WARN_ON(bus1_queue_peek(&qb, &has_continue) != &n1b);
	WARN_ON(has_continue);
	bus1_queue_remove(&qb, NULL, &n1b);
	WARN_ON(bus1_queue_peek(&qb, &has_continue) != &n2b);
	WARN_ON(has_continue);
	bus1_queue_remove(&qb, NULL, &n2b);

	bus1_queue_deinit(&q1);
	bus1_queue_deinit(&q2);
	bus1_queue_deinit(&qa);
	bus1_queue_deinit(&qb);
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

	/* create a different user */
	user2 = bus1_user_ref_by_uid(uid2);
	WARN_ON(!user2);
	WARN_ON(user1 == user2);
	WARN_ON(__kuid_val(user2->uid) != 2);

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

static void bus1_test_handle_basic(void)
{
	struct bus1_handle *t, *h[3] = {};
	struct bus1_peer *p[2] = {};
	const struct cred *cred = current_cred();

	/* peer setup */

	p[0] = bus1_peer_new(cred);
	p[1] = bus1_peer_new(cred);
	WARN_ON(IS_ERR_OR_NULL(p[0]) || IS_ERR_OR_NULL(p[1]));
	WARN_ON(!bus1_peer_acquire(p[0]));
	WARN_ON(!bus1_peer_acquire(p[1]));

	/* test no-ops */

	WARN_ON(bus1_handle_ref(NULL));
	WARN_ON(bus1_handle_unref(NULL));
	WARN_ON(bus1_handle_acquire(NULL, false));
	WARN_ON(bus1_handle_release(NULL, false));

	/* test anchor creation */

	h[0] = bus1_handle_new_anchor(p[0]);
	WARN_ON(IS_ERR_OR_NULL(h[0]));
	WARN_ON(atomic_read(&h[0]->ref.refcount) != 1);
	t = bus1_handle_unref(h[0]);
	WARN_ON(t);

	/* test remote creation based on anchor */

	h[0] = bus1_handle_new_anchor(p[0]);
	WARN_ON(IS_ERR_OR_NULL(h[0]));
	h[1] = bus1_handle_new_remote(p[1], h[0]);
	WARN_ON(IS_ERR_OR_NULL(h[1]));

	WARN_ON(atomic_read(&h[0]->ref.refcount) < 2);
	WARN_ON(atomic_read(&h[1]->ref.refcount) != 1);
	bus1_handle_unref(h[1]);
	WARN_ON(atomic_read(&h[0]->ref.refcount) != 1);
	bus1_handle_unref(h[0]);

	/* test remote creation based on existing remote */

	h[0] = bus1_handle_new_anchor(p[0]);
	WARN_ON(IS_ERR_OR_NULL(h[0]));
	h[1] = bus1_handle_new_remote(p[1], h[0]);
	WARN_ON(IS_ERR_OR_NULL(h[1]));
	h[2] = bus1_handle_new_remote(p[1], h[1]);
	WARN_ON(IS_ERR_OR_NULL(h[2]));

	WARN_ON(atomic_read(&h[0]->ref.refcount) < 3);
	WARN_ON(atomic_read(&h[1]->ref.refcount) != 1);
	WARN_ON(atomic_read(&h[2]->ref.refcount) != 1);
	bus1_handle_unref(h[2]);
	bus1_handle_unref(h[1]);
	WARN_ON(atomic_read(&h[0]->ref.refcount) != 1);
	bus1_handle_unref(h[0]);

	/* peer cleanup */

	bus1_peer_release(p[1]);
	bus1_peer_release(p[0]);
	p[1] = bus1_peer_free(p[1]);
	p[0] = bus1_peer_free(p[0]);
}

static void bus1_test_handle_lifetime(void)
{
	static const unsigned int n_tests = 10;
	const struct cred *cred = current_cred();
	struct bus1_handle *t, *h[5] = {};
	struct bus1_peer *p[3] = {};
	unsigned int i, j;

	/*
	 * This is just a simple loop that runs a bunch of tests and re-creates
	 * a set of fresh handles for each test.
	 */

	for (i = 0, j = 0; i < n_tests; ++i) {
		p[0] = bus1_peer_new(cred);
		p[1] = bus1_peer_new(cred);
		p[2] = bus1_peer_new(cred);
		WARN_ON(IS_ERR_OR_NULL(p[0]) ||
		        IS_ERR_OR_NULL(p[1]) ||
		        IS_ERR_OR_NULL(p[2]));
		WARN_ON(!bus1_peer_acquire(p[0]));
		WARN_ON(!bus1_peer_acquire(p[1]));
		WARN_ON(!bus1_peer_acquire(p[2]));

		switch (i) {
		case 0:
			/* test normal acquisition and release */
			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			t = bus1_handle_release(h[1], false);
			WARN_ON(t);
			t = bus1_handle_release(h[0], false);
			WARN_ON(t);

			++j;
			break;
		case 1:
			/*
			 * We acquire anchor and remote and then verify
			 * re-attach on the remote works fine.
			 */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_handle_release(h[1], false);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_handle_release(h[1], false);

			bus1_handle_release(h[0], false);

			++j;
			break;
		case 2:
			/*
			 * We acquire both anchor and remote and then try
			 * acquiring a different remote on the same peer as the
			 * previous remote. It must detect the conflict, unref
			 * it and instead return an acquired reference to the
			 * valid remote.
			 */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));
			h[2] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[2]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);

			bus1_handle_ref(h[2]);
			/* unrefs h[2], acquires and refs h[1] */
			t = bus1_handle_acquire(h[2], false);
			WARN_ON(t != h[1]);
			bus1_handle_release(t, false);
			bus1_handle_unref(t);

			bus1_handle_release(h[1], false);
			bus1_handle_release(h[0], false);

			++j;
			break;
		case 3:
			/*
			 * We acquire both anchor and remote and then try
			 * looking them up by their peer.
			 */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_ref_by_other(p[0], h[0]);
			WARN_ON(!t);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[0], h[1]);
			WARN_ON(!t);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[1], h[0]);
			WARN_ON(t);
			t = bus1_handle_ref_by_other(p[1], h[1]);
			WARN_ON(t);

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);

			t = bus1_handle_ref_by_other(p[0], h[0]);
			WARN_ON(t != h[0]);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[0], h[1]);
			WARN_ON(t != h[0]);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[1], h[0]);
			WARN_ON(t != h[1]);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[1], h[1]);
			WARN_ON(t != h[1]);
			bus1_handle_unref(t);

			bus1_handle_release(h[1], false);
			bus1_handle_release(h[0], false);

			t = bus1_handle_ref_by_other(p[0], h[0]);
			WARN_ON(!t);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[0], h[1]);
			WARN_ON(!t);
			bus1_handle_unref(t);
			t = bus1_handle_ref_by_other(p[1], h[0]);
			WARN_ON(t);
			t = bus1_handle_ref_by_other(p[1], h[1]);
			WARN_ON(t);

			++j;
			break;
		case 4:
			/*
			 * Test inverse releases: first release anchor then the
			 * now stale remote.
			 */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);

			bus1_handle_release(h[0], false);
			bus1_handle_release(h[1], false);

			++j;
			break;
		case 5:
			/* test multi-acquisition */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_handle_release(h[1], false);
			bus1_handle_release(h[1], false);

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			bus1_handle_release(h[0], false);

			bus1_handle_release(h[0], false);

			++j;
			break;
		case 6:
			/* test remote release on disconnected peer */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_active_deactivate(&p[1]->active);
			bus1_handle_release(h[1], false);

			bus1_handle_release(h[0], false);

			++j;
			break;
		case 7:
			/* test anchor release on disconnected peer */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_active_deactivate(&p[0]->active);
			bus1_handle_release(h[1], false);

			bus1_handle_release(h[0], false);

			++j;
			break;
		case 8:
			/* test full release on disconnected peers */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			bus1_active_deactivate(&p[0]->active);
			bus1_active_deactivate(&p[1]->active);
			bus1_handle_release(h[1], false);

			bus1_handle_release(h[0], false);

			++j;
			break;
		case 9:
			/* test acquisition after release */

			h[0] = bus1_handle_new_anchor(p[0]);
			WARN_ON(IS_ERR_OR_NULL(h[0]));
			h[1] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[1]));
			h[2] = bus1_handle_new_remote(p[1], h[0]);
			WARN_ON(IS_ERR_OR_NULL(h[2]));

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			bus1_handle_release(h[0], false);

			t = bus1_handle_acquire(h[1], false);
			WARN_ON(t != h[1]);
			/* after release, there is no conflict detection */
			t = bus1_handle_acquire(h[2], false);
			WARN_ON(t != h[2]);
			bus1_handle_release(h[2], false);
			bus1_handle_release(h[1], false);

			t = bus1_handle_acquire(h[0], false);
			WARN_ON(t != h[0]);
			bus1_handle_release(h[0], false);

			++j;
			break;
		default:
			break;
		}

		if (h[4]) {
			WARN_ON(atomic_read(&h[4]->ref.refcount) != 1);
			h[4] = bus1_handle_unref(h[4]);
		}
		if (h[3]) {
			WARN_ON(atomic_read(&h[3]->ref.refcount) != 1);
			h[3] = bus1_handle_unref(h[3]);
		}
		if (h[2]) {
			WARN_ON(atomic_read(&h[2]->ref.refcount) != 1);
			h[2] = bus1_handle_unref(h[2]);
		}
		if (h[1]) {
			WARN_ON(atomic_read(&h[1]->ref.refcount) != 1);
			h[1] = bus1_handle_unref(h[1]);
		}
		if (h[0]) {
			WARN_ON(atomic_read(&h[0]->ref.refcount) != 1);
			h[0] = bus1_handle_unref(h[0]);
		}

		bus1_peer_release(p[2]);
		bus1_peer_release(p[1]);
		bus1_peer_release(p[0]);
		bus1_peer_free(p[2]);
		bus1_peer_free(p[1]);
		bus1_peer_free(p[0]);
	}
	WARN_ON(i != j);
}

static void bus1_test_handle_ids(void)
{
	struct bus1_handle *t, *h[2] = {};
	struct bus1_peer *p[2] = {};
	const struct cred *cred = current_cred();
	bool is_new;
	u64 id;

	p[0] = bus1_peer_new(cred);
	p[1] = bus1_peer_new(cred);
	WARN_ON(IS_ERR_OR_NULL(p[0]) || IS_ERR_OR_NULL(p[1]));
	WARN_ON(!bus1_peer_acquire(p[0]));
	WARN_ON(!bus1_peer_acquire(p[1]));

	bus1_mutex_lock2(&p[0]->local.lock, &p[1]->local.lock);

	/* test non-existent remote lookup (must fail) */

	id = BUS1_HANDLE_FLAG_REMOTE;
	t = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(!IS_ERR(t) || PTR_ERR(t) != -ENXIO);
	id = BUS1_HANDLE_FLAG_REMOTE | BUS1_HANDLE_FLAG_MANAGED;
	t = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(!IS_ERR(t) || PTR_ERR(t) != -ENXIO);

	/* test non-existent node lookup (creates and links node) */

	id = 0;
	h[0] = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(IS_ERR_OR_NULL(h[0]));

	t = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(t != h[0]);
	bus1_handle_unref(t);

	bus1_handle_forget(h[0]);
	bus1_handle_unref(h[0]);

	/* test handle export and re-export */

	h[0] = bus1_handle_new_anchor(p[0]);
	WARN_ON(IS_ERR_OR_NULL(h[0]));
	h[1] = bus1_handle_new_remote(p[1], h[0]);
	WARN_ON(IS_ERR_OR_NULL(h[1]));
	t = bus1_handle_acquire(h[0], false);
	WARN_ON(t != h[0]);
	t = bus1_handle_acquire(h[1], false);
	WARN_ON(t != h[1]);

	WARN_ON(h[1]->id != BUS1_HANDLE_INVALID);
	bus1_handle_export(h[1]);
	WARN_ON(h[1]->id == BUS1_HANDLE_INVALID);
	id = h[1]->id;
	t = bus1_handle_import(p[1], id, &is_new);
	WARN_ON(t != h[1]);
	bus1_handle_unref(t);
	bus1_handle_forget(h[1]);
	WARN_ON(h[1]->id != BUS1_HANDLE_INVALID);

	t = bus1_handle_import(p[1], id, &is_new);
	WARN_ON(!IS_ERR(t) || PTR_ERR(t) != -ENXIO);

	bus1_handle_export(h[1]);
	WARN_ON(h[1]->id == BUS1_HANDLE_INVALID);
	WARN_ON(h[1]->id == id);
	bus1_handle_forget(h[1]);

	t = bus1_handle_release(h[1], false);
	t = bus1_handle_release(h[0], false);
	h[1] = bus1_handle_unref(h[1]);
	h[0] = bus1_handle_unref(h[0]);

	/* cleanup */

	bus1_mutex_unlock2(&p[0]->local.lock, &p[1]->local.lock);

	bus1_peer_release(p[1]);
	bus1_peer_release(p[0]);
	p[1] = bus1_peer_free(p[1]);
	p[0] = bus1_peer_free(p[0]);
}

int bus1_tests_run(void)
{
	pr_info("run selftests..\n");
	bus1_test_active();
	bus1_test_pool();
	bus1_test_queue();
	bus1_test_flist();
	bus1_test_user();
	bus1_test_handle_basic();
	bus1_test_handle_lifetime();
	bus1_test_handle_ids();
	return 0;
}
