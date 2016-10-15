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
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include "main.h"
#include "peer.h"
#include "user.h"
#include "util.h"

#define BUS1_INTERNAL_UID_INVALID ((unsigned int) -1)

static DEFINE_MUTEX(bus1_user_lock);
static DEFINE_IDR(bus1_user_idr);
static DEFINE_IDA(bus1_user_ida);

static unsigned short bus1_user_max_slices = 16383;
static unsigned short bus1_user_max_handles = 65535;
static unsigned int bus1_user_max_inflight_bytes = 16 * 1024 * 1024;
static unsigned short bus1_user_max_inflight_fds = 4096;

module_param_named(user_max_slices, bus1_user_max_slices, ushort, 0644);
module_param_named(user_max_handles, bus1_user_max_handles, ushort, 0644);
module_param_named(user_max_bytes, bus1_user_max_inflight_bytes, uint, 0644);
module_param_named(user_max_fds, bus1_user_max_inflight_fds, ushort, 0644);
MODULE_PARM_DESC(user_max_slices, "Max number of slices for each user.");
MODULE_PARM_DESC(user_max_handles, "Max number of handles for each user.");
MODULE_PARM_DESC(user_max_bytes, "Max number of bytes for each user.");
MODULE_PARM_DESC(user_max_fds, "Max number of fds for each user.");

/**
 * bus1_user_modexit() - clean up global resources of user accounting
 *
 * This function cleans up any remaining global resources that were allocated
 * by the user accounting helpers. The caller must make sure that no user
 * object is referenced anymore, before calling this. This function just clears
 * caches and verifies nothing is leaked.
 *
 * This is meant to be called on module-exit.
 */
void bus1_user_modexit(void)
{
	BUS1_WARN_ON(!idr_is_empty(&bus1_user_ida.idr));
	BUS1_WARN_ON(!idr_is_empty(&bus1_user_idr));
	ida_destroy(&bus1_user_ida);
	idr_destroy(&bus1_user_idr);
	idr_init(&bus1_user_idr);
	ida_init(&bus1_user_ida);
}

/**
 * bus1_user_limits_init() - initialize resource limit counter
 * @limits:		object to initialize
 * @source:		source to initialize from, or NULL
 *
 * This initializes the resource-limit counter @limit. The initial limits are
 * taken from @source, if given. If NULL, the global default limits are taken.
 */
void bus1_user_limits_init(struct bus1_user_limits *limits,
			   struct bus1_user *source)
{
	if (source) {
		limits->max_slices = source->limits.max_slices;
		limits->max_handles = source->limits.max_handles;
		limits->max_inflight_bytes = source->limits.max_inflight_bytes;
		limits->max_inflight_fds = source->limits.max_inflight_fds;
	} else {
		limits->max_slices = bus1_user_max_slices;
		limits->max_handles = bus1_user_max_handles;
		limits->max_inflight_bytes = bus1_user_max_inflight_bytes;
		limits->max_inflight_fds = bus1_user_max_inflight_fds;
	}

	atomic_set(&limits->n_slices, limits->max_slices);
	atomic_set(&limits->n_handles, limits->max_handles);
	atomic_set(&limits->n_inflight_bytes, limits->max_inflight_bytes);
	atomic_set(&limits->n_inflight_fds, limits->max_inflight_fds);
}

/**
 * bus1_user_limits_deinit() - deinitialize source limit counter
 * @limits:		object to deinitialize
 *
 * This should be called on destruction of @limits. It verifies the correctness
 * of the limits and emits warnings if something went wrong.
 */
void bus1_user_limits_deinit(struct bus1_user_limits *limits)
{
	WARN_ON(atomic_read(&limits->n_slices) !=
		limits->max_slices);
	WARN_ON(atomic_read(&limits->n_handles) !=
		limits->max_handles);
	WARN_ON(atomic_read(&limits->n_inflight_bytes) !=
		limits->max_inflight_bytes);
	WARN_ON(atomic_read(&limits->n_inflight_fds) !=
		limits->max_inflight_fds);
}

static struct bus1_user *bus1_user_new(void)
{
	struct bus1_user *user;

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return ERR_PTR(-ENOMEM);

	kref_init(&user->ref);
	mutex_init(&user->lock);
	user->id = BUS1_INTERNAL_UID_INVALID;
	user->uid = INVALID_UID;
	bus1_user_limits_init(&user->limits, NULL);

	return user;
}

static void bus1_user_free(struct kref *ref)
{
	struct bus1_user *user = container_of(ref, struct bus1_user, ref);

	lockdep_assert_held(&bus1_user_lock);

	if (likely(uid_valid(user->uid)))
		idr_remove(&bus1_user_idr, __kuid_val(user->uid));

	/* drop the id from the ida if it was initialized */
	if (user->id != BUS1_INTERNAL_UID_INVALID)
		ida_simple_remove(&bus1_user_ida, user->id);

	bus1_user_limits_deinit(&user->limits);
	mutex_destroy(&user->lock);
	kfree_rcu(user, rcu);
}

/**
 * bus1_user_ref_by_uid() - get a user object for a uid
 * @uid:		uid of the user
 *
 * Find and return the user object for the uid if it exists, otherwise create
 * it first. This function may take the bus1_user_lock.
 *
 * Return: A user object for the given uid, ERR_PTR on failure.
 */
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid)
{
	struct bus1_user *user;
	int r;

	if (BUS1_WARN_ON(!uid_valid(uid)))
		return ERR_PTR(-ENOTRECOVERABLE);

	/* fast-path: acquire reference via rcu */
	rcu_read_lock();
	user = idr_find(&bus1_user_idr, __kuid_val(uid));
	if (user && !kref_get_unless_zero(&user->ref))
		user = NULL;
	rcu_read_unlock();
	if (user)
		return user;

	/* slow-path: try again with IDR locked */
	mutex_lock(&bus1_user_lock);
	user = idr_find(&bus1_user_idr, __kuid_val(uid));
	if (likely(!bus1_user_ref(user))) {
		user = bus1_user_new();
		if (IS_ERR(user))
			goto exit;

		r = ida_simple_get(&bus1_user_ida, 0, 0, GFP_KERNEL);
		if (r < 0) {
			kref_put(&user->ref, bus1_user_free);
			user = ERR_PTR(r);
			goto exit;
		}
		user->id = r;

		user->uid = uid;
		r = idr_alloc(&bus1_user_idr, user, __kuid_val(uid),
			       __kuid_val(uid) + 1, GFP_KERNEL);
		if (r < 0) {
			user->uid = INVALID_UID; /* couldn't insert */
			kref_put(&user->ref, bus1_user_free);
			user = ERR_PTR(r);
		}
	}

exit:
	mutex_unlock(&bus1_user_lock);

	return user;
}

/**
 * bus1_user_ref() - acquire reference
 * @user:	user to acquire, or NULL
 *
 * Acquire an additional reference to a user-object. The caller must already
 * own a reference.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @user is returned.
 */
struct bus1_user *bus1_user_ref(struct bus1_user *user)
{
	if (user)
		kref_get(&user->ref);
	return user;
}

/**
 * bus1_user_unref() - release reference
 * @user:	user to release, or NULL
 *
 * Release a reference to a user-object.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_user *bus1_user_unref(struct bus1_user *user)
{
	if (user) {
		if (kref_put_mutex(&user->ref, bus1_user_free, &bus1_user_lock))
			mutex_unlock(&bus1_user_lock);
	}

	return NULL;
}

/**
 * bus1_user_quota_init() - initialize quota object
 * @quota:		quota object to initialize
 *
 * Initialize all fields of a quota object.
 */
void bus1_user_quota_init(struct bus1_user_quota *quota)
{
	quota->n_stats = 0;
	quota->stats = NULL;
}

/**
 * bus1_user_quota_destroy() - destroy quota object
 * @quota:		quota object to destroy, or NULL
 *
 * Destroy and deallocate a quota object. All linked resources are freed, and
 * the object is ready for re-use.
 *
 * If NULL is passed, this is a no-op.
 */
void bus1_user_quota_destroy(struct bus1_user_quota *quota)
{
	if (!quota)
		return;

	kfree(quota->stats);
	bus1_user_quota_init(quota);
}

static struct bus1_user_stats *
bus1_user_quota_query(struct bus1_user_quota *quota,
		      struct bus1_user *user)
{
	struct bus1_user_stats *stats;
	size_t n;

	if (user->id >= quota->n_stats) {
		/* allocate some additional space, but prevent overflow */
		n = max(ALIGN(user->id, 8) + 8, user->id);
		stats = krealloc(quota->stats, n * sizeof(*stats), GFP_KERNEL);
		if (!stats)
			return ERR_PTR(-ENOMEM);

		memset(stats + quota->n_stats, 0,
		       (n - quota->n_stats) * sizeof(*stats));
		quota->stats = stats;
		quota->n_stats = n;
	}

	return quota->stats + user->id;
}

static int bus1_user_quota_charge_one(atomic_t *remaining,
				      size_t share,
				      size_t charge)
{
	size_t reserved;

	/*
	 * Try charging a single resource type. If limits are exceeded, return
	 * an error-code, otherwise apply charges.
	 *
	 * @remaining: per-user atomic that counts all instances of this
	 *             resource for this single user. It is initially set to the
	 *             limit for this user. For each accounted resource, we
	 *             decrement it. Thus, it must not drop below 0, or you
	 *             exceeded your quota.
	 * @share:     current amount of resources that the acting task has in
	 *             the local peer.
	 * @charge:    number of resources to charge with this operation
	 *
	 * We try charging @charge on @remaining. The applied logic is: The
	 * caller is not allowed to account for more than the half of the
	 * remaining space (including what its current share). That is, if 'n'
	 * free resources are remaining, then after charging @charge, it must
	 * not drop below @share+@charge. That is, the remaining resources after
	 * the charge are still at least as big as what the caller has charged
	 * in total.
	 */

	reserved = share + charge * 2;

	/* check for overflow */
	if (charge > charge * 2 || share > reserved || charge * 2 > reserved)
		return -EDQUOT;

	if (!bus1_atomic_sub_if_ge(remaining, charge, reserved))
		return -EDQUOT;

	return 0;
}

/**
 * bus1_user_quota_charge() - try charging a user
 * @peer:		peer with quota to operate on
 * @user:		user to charge
 * @n_bytes:		number of bytes to charge
 * @n_handles:		number of handles to charge
 * @n_fds:		number of FDs to charge
 *
 * This charges @user for the given resources on @peer. If the charge would
 * exceed the given quotas at this time, the function fails without making any
 * charge. If the charge is successful, the available resources are adjusted
 * accordingly both locally on @peer and globally on the associated user.
 *
 * This charges for _one_ message with a size of @n_bytes, carrying
 * @n_handles handles and @n_fds file descriptors as payload.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_user_quota_charge(struct bus1_peer *peer,
			   struct bus1_user *user,
			   size_t n_bytes,
			   size_t n_handles,
			   size_t n_fds)
{
	struct bus1_user_stats *stats;
	int r;

	lockdep_assert_held(&peer->lock);

	stats = bus1_user_quota_query(&peer->quota, user);
	if (IS_ERR(stats))
		return PTR_ERR(stats);

	/*
	 * For each type of quota, we usually follow a very simple rule: A
	 * given user can acquire half of the total in-flight budget that is
	 * not used by any other user.
	 */

	BUILD_BUG_ON((typeof(bus1_user_max_slices))-1 > U16_MAX);
	BUILD_BUG_ON((typeof(bus1_user_max_handles))-1 > U16_MAX);
	BUILD_BUG_ON((typeof(bus1_user_max_inflight_bytes))-1 > U32_MAX);
	BUILD_BUG_ON((typeof(bus1_user_max_inflight_fds))-1 > U16_MAX);

	r = bus1_user_quota_charge_one(&peer->user->limits.n_slices,
				       stats->n_slices, 1);
	if (r < 0)
		return r;

	r = bus1_user_quota_charge_one(&peer->user->limits.n_handles,
				       stats->n_handles, n_handles);
	if (r < 0)
		goto error_slices;

	r = bus1_user_quota_charge_one(&peer->user->limits.n_inflight_bytes,
				       stats->n_bytes, n_bytes);
	if (r < 0)
		goto error_handles;

	r = bus1_user_quota_charge_one(&peer->user->limits.n_inflight_fds,
				       stats->n_fds, n_fds);
	if (r < 0)
		goto error_bytes;

	/* charge the local quotas */
	stats->n_slices += 1;
	stats->n_handles += n_handles;
	stats->n_bytes += n_bytes;
	stats->n_fds += n_fds;

	return 0;

error_bytes:
	atomic_add(n_bytes, &peer->user->limits.n_inflight_bytes);
error_handles:
	atomic_add(n_handles, &peer->user->limits.n_handles);
error_slices:
	atomic_inc(&peer->user->limits.n_slices);
	return r;
}

/**
 * bus1_user_quota_discharge() - discharge a user
 * @peer:		peer with quota to operate on
 * @user:		user to discharge
 * @n_bytes:		number of bytes to discharge
 * @n_handles:		number of handles to discharge
 * @n_fds:		number of FDs to discharge
 *
 * This reverts a single charge done via bus1_user_quota_charge(). It
 * discharges a single message with a slice of size @n_bytes, @n_handles handles
 * and @n_fds file-descriptors.
 */
void bus1_user_quota_discharge(struct bus1_peer *peer,
			       struct bus1_user *user,
			       size_t n_bytes,
			       size_t n_handles,
			       size_t n_fds)
{
	struct bus1_user_stats *stats;

	lockdep_assert_held(&peer->lock);

	stats = bus1_user_quota_query(&peer->quota, user);
	if (WARN_ON(IS_ERR_OR_NULL(stats)))
		return;

	BUS1_WARN_ON(stats->n_slices < 1);
	BUS1_WARN_ON(stats->n_handles < n_handles);
	BUS1_WARN_ON(stats->n_bytes < n_bytes);
	BUS1_WARN_ON(stats->n_fds < n_fds);

	stats->n_slices -= 1;
	stats->n_handles -= n_handles;
	stats->n_bytes -= n_bytes;
	stats->n_fds -= n_fds;
	atomic_inc(&peer->user->limits.n_slices);
	atomic_add(n_handles, &peer->user->limits.n_handles);
	atomic_add(n_bytes, &peer->user->limits.n_inflight_bytes);
	atomic_add(n_fds, &peer->user->limits.n_inflight_fds);
}

/**
 * bus1_user_quota_commit() - commit a quota charge
 * @peer:		peer with quota to operate on
 * @user:		user to commit for
 * @n_bytes:		number of bytes to commit
 * @n_handles:		number of handles to commit
 * @n_fds:		number of FDs to commit
 *
 * Commit a quota charge to the receiving peer. This de-accounts the in-flight
 * charges, but keeps the actual object charges on the receiver. The caller must
 * make sure the actual objects are de-accounted once they are destructed.
 */
void bus1_user_quota_commit(struct bus1_peer *peer,
			    struct bus1_user *user,
			    size_t n_bytes,
			    size_t n_handles,
			    size_t n_fds)
{
	struct bus1_user_stats *stats;

	lockdep_assert_held(&peer->lock);

	stats = bus1_user_quota_query(&peer->quota, user);
	if (WARN_ON(IS_ERR_OR_NULL(stats)))
		return;

	BUS1_WARN_ON(stats->n_slices < 1);
	BUS1_WARN_ON(stats->n_handles < n_handles);
	BUS1_WARN_ON(stats->n_bytes < n_bytes);
	BUS1_WARN_ON(stats->n_fds < n_fds);

	stats->n_slices -= 1;
	stats->n_handles -= n_handles;
	stats->n_bytes -= n_bytes;
	stats->n_fds -= n_fds;

	/* discharge any inflight-only resources */
	atomic_add(n_bytes, &peer->user->limits.n_inflight_bytes);
	atomic_add(n_fds, &peer->user->limits.n_inflight_fds);
}
