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
#include "user.h"

static DEFINE_MUTEX(bus1_user_lock);
static DEFINE_IDR(bus1_user_idr);

static unsigned int bus1_user_max_slices = 16384;
static unsigned int bus1_user_max_handles = 65536;
static unsigned int bus1_user_max_inflight_bytes = 16 * 1024 * 1024;
static unsigned int bus1_user_max_inflight_fds = 4096;

module_param_named(user_slices_max, bus1_user_max_slices,
		   uint, 0644);
module_param_named(user_handles_max, bus1_user_max_handles,
		   uint, 0644);
module_param_named(user_inflight_bytes_max, bus1_user_max_inflight_bytes,
		   uint, 0644);
module_param_named(user_inflight_fds_max, bus1_user_max_inflight_fds,
		   uint, 0644);
MODULE_PARM_DESC(user_max_slices,
		 "Max number of slices for each user.");
MODULE_PARM_DESC(user_max_handles,
		 "Max number of handles for each user.");
MODULE_PARM_DESC(user_max_inflight_bytes,
		 "Max number of inflight bytes for each user.");
MODULE_PARM_DESC(user_max_inflight_fds,
		 "Max number of inflight fds for each user.");

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
	WARN_ON(!idr_is_empty(&bus1_user_idr));
	idr_destroy(&bus1_user_idr);
	idr_init(&bus1_user_idr);
}

static struct bus1_user_usage *bus1_user_usage_new(void)
{
	struct bus1_user_usage *usage;

	usage = kzalloc(sizeof(*usage), GFP_KERNEL);
	if (!usage)
		return ERR_PTR(-ENOMEM);

	return usage;
}

static struct bus1_user_usage *
bus1_user_usage_free(struct bus1_user_usage *usage)
{
	if (usage) {
		WARN_ON(atomic_read(&usage->n_slices));
		WARN_ON(atomic_read(&usage->n_handles));
		WARN_ON(atomic_read(&usage->n_bytes));
		WARN_ON(atomic_read(&usage->n_fds));
		kfree(usage);
	}

	return NULL;
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

	atomic_set(&limits->n_usages, 0);
	idr_init(&limits->usages);
	mutex_init(&limits->lock);
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
	struct bus1_user_usage *usage;
	int i;

	idr_for_each_entry(&limits->usages, usage, i) {
		bus1_user_usage_free(usage);
		atomic_dec(&limits->n_usages);
	}

	mutex_destroy(&limits->lock);
	idr_destroy(&limits->usages);
	WARN_ON(atomic_read(&limits->n_usages) != 0);

	WARN_ON(atomic_read(&limits->n_slices) !=
		limits->max_slices);
	WARN_ON(atomic_read(&limits->n_handles) !=
		limits->max_handles);
	WARN_ON(atomic_read(&limits->n_inflight_bytes) !=
		limits->max_inflight_bytes);
	WARN_ON(atomic_read(&limits->n_inflight_fds) !=
		limits->max_inflight_fds);
}

static struct bus1_user_usage *
bus1_user_limits_map(struct bus1_user_limits *limits, struct bus1_user *actor)
{
	struct bus1_user_usage *usage;
	int r;

	/* fast-path: acquire usage object via rcu */
	rcu_read_lock();
	usage = idr_find(&limits->usages, __kuid_val(actor->uid));
	rcu_read_unlock();
	if (usage)
		return usage;

	/* slow-path: try again with IDR locked */
	mutex_lock(&limits->lock);
	usage = idr_find(&limits->usages, __kuid_val(actor->uid));
	if (likely(!usage)) {
		usage = bus1_user_usage_new();
		if (!IS_ERR(usage)) {
			r = idr_alloc(&limits->usages, usage,
				      __kuid_val(actor->uid),
				      __kuid_val(actor->uid) + 1, GFP_KERNEL);
			if (r < 0) {
				bus1_user_usage_free(usage);
				usage = ERR_PTR(r);
			} else {
				atomic_inc(&limits->n_usages);
			}
		}
	}
	mutex_unlock(&limits->lock);

	return usage;
}

static struct bus1_user *bus1_user_new(void)
{
	struct bus1_user *user;

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return ERR_PTR(-ENOMEM);

	kref_init(&user->ref);
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
	bus1_user_limits_deinit(&user->limits);
	kfree_rcu(user, rcu);
}

/**
 * bus1_user_ref_by_uid() - get a user object for a uid
 * @uid:		uid of the user
 *
 * Find and return the user object for the uid if it exists, otherwise create
 * it first.
 *
 * Return: A user object for the given uid, ERR_PTR on failure.
 */
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid)
{
	struct bus1_user *user;
	int r;

	if (WARN_ON(!uid_valid(uid)))
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
		if (!IS_ERR(user)) {
			user->uid = uid;
			r = idr_alloc(&bus1_user_idr, user, __kuid_val(uid),
				      __kuid_val(uid) + 1, GFP_KERNEL);
			if (r < 0) {
				user->uid = INVALID_UID; /* couldn't insert */
				kref_put(&user->ref, bus1_user_free);
				user = ERR_PTR(r);
			}
		}
	}
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
 * bus1_user_charge() - charge a user resource
 * @global:		global resource to charge on
 * @local:		local resource to charge on
 * @charge:		charge to apply
 *
 * This charges @charge on two resource counters. Only if both charges apply,
 * this returns success. It is an error to call this with negative charges.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_user_charge(atomic_t *global, atomic_t *local, int charge)
{
	int v;

	WARN_ON(charge < 0);

	if (!charge)
		return 0;

	v = bus1_atomic_add_if_ge(global, -charge, charge);
	if (v < charge)
		return -EDQUOT;

	v = bus1_atomic_add_if_ge(local, -charge, charge);
	if (v < charge) {
		atomic_add(charge, global);
		return -EDQUOT;
	}

	return 0;
}

/**
 * bus1_user_discharge() - discharge a user resource
 * @global:		global resource to charge on
 * @local:		local resource to charge on
 * @charge:		charge to apply
 *
 * This discharges @charge on two resource counters. This always succeeds. It
 * is an error to call this with a negative charge.
 */
void bus1_user_discharge(atomic_t *global, atomic_t *local, int charge)
{
	WARN_ON(charge < 0);
	atomic_add(charge, local);
	atomic_add(charge, global);
}

static int bus1_user_charge_quota_one(atomic_t *remaining,
				      atomic_t *share,
				      int users,
				      int charge)
{
	int v, new_share, r;

	WARN_ON(charge < 0);
	WARN_ON(users < 1);

	/*
	 * Try charging a single resource type. If limits are exceeded, return
	 * an error-code, otherwise apply charges.
	 *
	 * @remaining: per-user atomic that counts all instances of this
	 *             resource for this single user. It is initially set to the
	 *             limit for this user. For each accounted resource, we
	 *             decrement it. Thus, it must not drop below 0, or you
	 *             exceeded your quota.
	 * @share:     current amount of resources that the acting user has
	 *             consumed from the receiving user. This is an upper bound,
	 *             it is possible for this to be momentarily charged charges
	 *             that do not end up being applied to the user limits
	 *             (which are then reverted below).
	 * @users:     an estimation of how many other users we want to share
	 *             the remaining resources
	 * @charge:    number of resources to charge with this operation
	 *
	 * We try charging @charge on @remaining. The logic applied is: The
	 * caller is not allowed to account for more than an n'th of the
	 * remaining space (including its current share), where 'n' is the
	 * number of users we assume to be sharing the resources. In other
	 * words, after charging @charge, the remaining resources remaining must
	 * not drop below (@share + @charge) * @users. That is, the remaining
	 * resources after the charge are still at least as large as what the
	 * caller has charged in total, multiplied by the number of other active
	 * users.
	 */

	/*
	 * This implies a memory barrier, so @share is guaranteed to be adjusted
	 * before @remaining is charged.
	 */
	new_share = atomic_add_return(charge, share);

	/* check for overflow */
	if (unlikely(new_share > (INT_MAX / users))) {
		r = -EDQUOT;
		goto revert_share;
	}

	v = bus1_atomic_add_if_ge(remaining, -charge, new_share * users);
	if (v < charge) {
		r = -EDQUOT;
		goto revert_share;
	}

	return 0;

revert_share:
	atomic_sub(charge, share);
	return r;
}

/**
 * bus1_user_charge_quota() - charge quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This charges the given resources on @user for user @actor.
 *
 * It is an error to call this with a negative charge. A charge might fail if
 * it would exceed the quota. Note that a single call is always atomic, so
 * either all succeed or all fail.
 *
 * Several calls to this function may race each other, it may happen that trying
 * to apply two charges simultaneously might fail whereas applying them one at a
 * time would have allow one to succeed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_user_charge_quota(struct bus1_user *user,
			   struct bus1_user *actor,
			   int n_slices,
			   int n_handles,
			   int n_bytes,
			   int n_fds)
{
	struct bus1_user_usage *usage;
	struct bus1_user_limits *limits = &user->limits;
	int r, n_usages;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	usage = bus1_user_limits_map(limits, actor);
	if (IS_ERR(usage))
		return PTR_ERR(usage);

	/*
	 * Share the resources between one more than the current number of known
	 * users. It is not important that this is precise, just that it exceeds
	 * the number of users at the time @usage was created.
	 */
	n_usages = atomic_read(&limits->n_usages);

	r = bus1_user_charge_quota_one(&limits->n_slices,
				       &usage->n_slices,
				       n_usages,
				       n_slices);
	if (r < 0)
		return r;

	r = bus1_user_charge_quota_one(&limits->n_handles,
				       &usage->n_handles,
				       n_usages,
				       n_handles);
	if (r < 0)
		goto revert_slices;

	r = bus1_user_charge_quota_one(&limits->n_inflight_bytes,
				       &usage->n_bytes,
				       n_usages,
				       n_bytes);
	if (r < 0)
		goto revert_handles;

	r = bus1_user_charge_quota_one(&limits->n_inflight_fds,
				       &usage->n_fds,
				       n_usages,
				       n_fds);
	if (r < 0)
		goto revert_bytes;

	return 0;

revert_bytes:
	atomic_add(n_bytes, &limits->n_inflight_bytes);
revert_handles:
	atomic_add(n_handles, &limits->n_handles);
revert_slices:
	atomic_add(n_slices, &limits->n_slices);
	return r;
}

/**
 * bus1_user_discharge_quota() - discharge quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This discharges the given resources on @user for user @actor.
 */
void bus1_user_discharge_quota(struct bus1_user *user,
			       struct bus1_user *actor,
			       int n_slices,
			       int n_handles,
			       int n_bytes,
			       int n_fds)
{
	struct bus1_user_usage *usage;
	struct bus1_user_limits *limits = &user->limits;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	usage = bus1_user_limits_map(limits, actor);
	WARN_ON(IS_ERR(usage));

	atomic_add(n_slices, &limits->n_slices);
	atomic_add(n_handles, &limits->n_handles);
	atomic_add(n_bytes, &limits->n_inflight_bytes);
	atomic_add(n_fds, &limits->n_inflight_fds);

	/*
	 * No memory barrier necessary, at worst reordering these sections will
	 * cause false negatives.
	 */
	atomic_sub(n_slices, &usage->n_slices);
	atomic_sub(n_handles, &usage->n_handles);
	atomic_sub(n_bytes, &usage->n_bytes);
	atomic_sub(n_fds, &usage->n_fds);
}

/**
 * bus1_user_commit_quota() - commit quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This commits the given resources on @user. Committing a quota means
 * discharging the usage objects but leaving the limits untouched.
 */
void bus1_user_commit_quota(struct bus1_user *user,
			    struct bus1_user *actor,
			    int n_slices,
			    int n_handles,
			    int n_bytes,
			    int n_fds)
{
	struct bus1_user_usage *usage;
	struct bus1_user_limits *limits = &user->limits;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	usage = bus1_user_limits_map(limits, actor);
	WARN_ON(IS_ERR(usage));

	atomic_add(n_bytes, &limits->n_inflight_bytes);
	atomic_add(n_fds, &limits->n_inflight_fds);

	/*
	 * No memory barrier necessary, at worst reordering these sections will
	 * cause false negatives.
	 */
	atomic_sub(n_slices, &usage->n_slices);
	atomic_sub(n_handles, &usage->n_handles);
	atomic_sub(n_bytes, &usage->n_bytes);
	atomic_sub(n_fds, &usage->n_fds);
}
