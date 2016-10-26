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

	idr_init(&limits->usages);
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

	idr_for_each_entry(&limits->usages, usage, i)
		bus1_user_usage_free(usage);

	idr_destroy(&limits->usages);

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

	usage = idr_find(&limits->usages, __kuid_val(actor->uid));
	if (usage)
		return usage;

	usage = bus1_user_usage_new();
	if (!IS_ERR(usage))
		return ERR_CAST(usage);

	r = idr_alloc(&limits->usages, usage, __kuid_val(actor->uid),
		      __kuid_val(actor->uid) + 1, GFP_KERNEL);
	if (r < 0) {
		bus1_user_usage_free(usage);
		return ERR_PTR(r);
	}

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
	mutex_init(&user->lock);
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
	mutex_destroy(&user->lock);
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

static int bus1_user_charge_one(atomic_t *global_remaining,
				atomic_t *local_remaining,
				int global_share,
				int local_share,
				int charge)
{
	int v, global_reserved, local_reserved;

	WARN_ON(charge < 0);

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

	if (charge > charge * 2)
		return -EDQUOT;

	global_reserved = global_share + charge * 2;

	if (global_share > global_reserved || charge * 2 > global_reserved)
		return -EDQUOT;

	v = bus1_atomic_add_if_ge(global_remaining, -charge, global_reserved);
	if (v < charge)
		return -EDQUOT;

	local_reserved = local_share + charge * 2;

	if (local_share > local_reserved || charge * 2 > local_reserved)
		return -EDQUOT;

	v = bus1_atomic_add_if_ge(local_remaining, -charge, local_reserved);
	if (v < charge) {
		atomic_add(charge, global_remaining);
		return -EDQUOT;
	}

	return 0;
}

static int bus1_user_charge_quota_locked(struct bus1_user_usage *q_global,
					 struct bus1_user_usage *q_local,
					 struct bus1_user_limits *l_global,
					 struct bus1_user_limits *l_local,
					 int n_slices,
					 int n_handles,
					 int n_bytes,
					 int n_fds)
{
	int r;

	r = bus1_user_charge_one(&l_global->n_slices, &l_local->n_slices,
				 atomic_read(&q_global->n_slices),
				 atomic_read(&q_local->n_slices),
				 n_slices);
	if (r < 0)
		return r;

	r = bus1_user_charge_one(&l_global->n_handles, &l_local->n_handles,
				 atomic_read(&q_global->n_handles),
				 atomic_read(&q_local->n_handles),
				 n_handles);
	if (r < 0)
		goto revert_slices;

	r = bus1_user_charge_one(&l_global->n_inflight_bytes,
				 &l_local->n_inflight_bytes,
				 atomic_read(&q_global->n_bytes),
				 atomic_read(&q_local->n_bytes),
				 n_bytes);
	if (r < 0)
		goto revert_handles;

	r = bus1_user_charge_one(&l_global->n_inflight_fds,
				 &l_local->n_inflight_fds,
				 atomic_read(&q_global->n_fds),
				 atomic_read(&q_local->n_fds),
				 n_fds);
	if (r < 0)
		goto revert_bytes;

	atomic_add(n_slices, &q_global->n_slices);
	atomic_add(n_handles, &q_global->n_handles);
	atomic_add(n_bytes, &q_global->n_bytes);
	atomic_add(n_fds, &q_global->n_fds);

	atomic_add(n_slices, &q_local->n_slices);
	atomic_add(n_handles, &q_local->n_handles);
	atomic_add(n_bytes, &q_local->n_bytes);
	atomic_add(n_fds, &q_local->n_fds);

	return 0;

revert_bytes:
	atomic_add(n_bytes, &l_local->n_inflight_bytes);
	atomic_add(n_bytes, &l_global->n_inflight_bytes);
revert_handles:
	atomic_add(n_handles, &l_local->n_handles);
	atomic_add(n_handles, &l_global->n_handles);
revert_slices:
	atomic_add(n_slices, &l_local->n_slices);
	atomic_add(n_slices, &l_global->n_slices);
	return r;
}

/**
 * bus1_user_charge_quota() - charge quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @limits:			local limits to charge on
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This charges the given resources on @user and @limits. It does both, local
 * and remote charges. It is all charged for user @actor.
 *
 * Negative charges always succeed. Positive charges might fail if quota is
 * denied. Note that a single call is always atomic, so either all succeed or
 * all fail. Hence, it makes little sense to mix negative and positive charges
 * in a single call.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_user_charge_quota(struct bus1_user *user,
			   struct bus1_user *actor,
			   struct bus1_user_limits *limits,
			   int n_slices,
			   int n_handles,
			   int n_bytes,
			   int n_fds)
{
	struct bus1_user_usage *u_usage, *usage;
	int r;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	mutex_lock(&user->lock);

	usage = bus1_user_limits_map(limits, actor);
	if (IS_ERR(usage)) {
		r = PTR_ERR(usage);
		goto exit;
	}

	u_usage = bus1_user_limits_map(&user->limits, actor);
	if (IS_ERR(u_usage)) {
		r = PTR_ERR(u_usage);
		goto exit;
	}

	r = bus1_user_charge_quota_locked(u_usage, usage, &user->limits,
					  limits, n_slices, n_handles,
					  n_bytes, n_fds);

exit:
	mutex_unlock(&user->lock);
	return r;
}

/**
 * bus1_user_discharge_quota() - discharge quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @l_local:			local limits to charge on
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This discharges the given resources on @user and @limits. It does both local
 * and remote charges. It is all discharged for user @actor.
 */
void bus1_user_discharge_quota(struct bus1_user *user,
			       struct bus1_user *actor,
			       struct bus1_user_limits *l_local,
			       int n_slices,
			       int n_handles,
			       int n_bytes,
			       int n_fds)
{
	struct bus1_user_usage *q_global, *q_local;
	struct bus1_user_limits *l_global = &user->limits;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	mutex_lock(&user->lock);

	q_local = bus1_user_limits_map(l_local, actor);
	if (WARN_ON(IS_ERR(q_local)))
		goto exit;

	q_global = bus1_user_limits_map(&user->limits, actor);
	if (WARN_ON(IS_ERR(q_global)))
		goto exit;

	atomic_sub(n_slices, &q_global->n_slices);
	atomic_sub(n_handles, &q_global->n_handles);
	atomic_sub(n_bytes, &q_global->n_bytes);
	atomic_sub(n_fds, &q_global->n_fds);

	atomic_sub(n_slices, &q_local->n_slices);
	atomic_sub(n_handles, &q_local->n_handles);
	atomic_sub(n_bytes, &q_local->n_bytes);
	atomic_sub(n_fds, &q_local->n_fds);

	atomic_add(n_slices, &l_global->n_slices);
	atomic_add(n_handles, &l_global->n_handles);
	atomic_add(n_bytes, &l_global->n_inflight_bytes);
	atomic_add(n_fds, &l_global->n_inflight_fds);

	atomic_add(n_slices, &l_local->n_slices);
	atomic_add(n_handles, &l_local->n_handles);
	atomic_add(n_bytes, &l_local->n_inflight_bytes);
	atomic_add(n_fds, &l_local->n_inflight_fds);

exit:
	mutex_unlock(&user->lock);
}

/**
 * bus1_user_commit_quota() - commit quota resources
 * @user:			user to charge on
 * @actor:			user to charge as
 * @l_local:			local limits to charge on
 * @n_slices:			number of slices to charge
 * @n_handles:			number of handles to charge
 * @n_bytes:			number of bytes to charge
 * @n_fds:			number of FDs to charge
 *
 * This commits the given resources on @user and @limits. Committing a quota
 * means discharging the usage objects but leaving the limits untouched.
 */
void bus1_user_commit_quota(struct bus1_user *user,
			    struct bus1_user *actor,
			    struct bus1_user_limits *l_local,
			    int n_slices,
			    int n_handles,
			    int n_bytes,
			    int n_fds)
{
	struct bus1_user_usage *q_global, *q_local;
	struct bus1_user_limits *l_global = &user->limits;

	WARN_ON(n_slices < 0 || n_handles < 0 || n_bytes < 0 || n_fds < 0);

	mutex_lock(&user->lock);

	q_local = bus1_user_limits_map(l_local, actor);
	if (WARN_ON(IS_ERR(q_local)))
		goto exit;

	q_global = bus1_user_limits_map(&user->limits, actor);
	if (WARN_ON(IS_ERR(q_global)))
		goto exit;

	atomic_sub(n_slices, &q_global->n_slices);
	atomic_sub(n_handles, &q_global->n_handles);
	atomic_sub(n_bytes, &q_global->n_bytes);
	atomic_sub(n_fds, &q_global->n_fds);

	atomic_sub(n_slices, &q_local->n_slices);
	atomic_sub(n_handles, &q_local->n_handles);
	atomic_sub(n_bytes, &q_local->n_bytes);
	atomic_sub(n_fds, &q_local->n_fds);

	atomic_add(n_bytes, &l_global->n_inflight_bytes);
	atomic_add(n_fds, &l_global->n_inflight_fds);

	atomic_add(n_bytes, &l_local->n_inflight_bytes);
	atomic_add(n_fds, &l_local->n_inflight_fds);

exit:
	mutex_unlock(&user->lock);
}
