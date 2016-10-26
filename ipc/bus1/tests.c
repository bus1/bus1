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
#include "handle.h"
#include "peer.h"
#include "tests.h"
#include "util/flist.h"

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

static void bus1_test_handle_basic(void)
{
	struct bus1_handle *t, *h[3] = {};
	struct bus1_peer *p[2] = {};

	/* peer setup */

	p[0] = bus1_peer_new();
	p[1] = bus1_peer_new();
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
	struct bus1_handle *t, *h[5] = {};
	struct bus1_peer *p[3] = {};
	unsigned int i, j;

	/*
	 * This is just a simple loop that runs a bunch of tests and re-creates
	 * a set of fresh handles for each test.
	 */

	for (i = 0, j = 0; i < n_tests; ++i) {
		p[0] = bus1_peer_new();
		p[1] = bus1_peer_new();
		p[2] = bus1_peer_new();
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
	bool is_new;
	u64 id;

	p[0] = bus1_peer_new();
	p[1] = bus1_peer_new();
	WARN_ON(IS_ERR_OR_NULL(p[0]) || IS_ERR_OR_NULL(p[1]));
	WARN_ON(!bus1_peer_acquire(p[0]));
	WARN_ON(!bus1_peer_acquire(p[1]));

	bus1_mutex_lock2(&p[0]->local.lock, &p[1]->local.lock);

	/* test non-existant remote lookup (must fail) */

	id = BUS1_HANDLE_FLAG_REMOTE;
	t = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(!IS_ERR(t) || PTR_ERR(t) != -ENXIO);
	id = BUS1_HANDLE_FLAG_REMOTE | BUS1_HANDLE_FLAG_MANAGED;
	t = bus1_handle_import(p[0], id, &is_new);
	WARN_ON(!IS_ERR(t) || PTR_ERR(t) != -ENXIO);

	/* test non-existant node lookup (creates and links node) */

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

static void bus1_test_user(void)
{
#if 0
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
#endif
}

static void bus1_test_quota(void)
{
#if 0
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
	bus1_pool_create(&peer.pool);

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
#endif
}

int bus1_tests_run(void)
{
	pr_info("run selftests..\n");
	bus1_test_flist();
	bus1_test_handle_basic();
	bus1_test_handle_lifetime();
	bus1_test_handle_ids();
	bus1_test_user();
	bus1_test_quota();
	return 0;
}
