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
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include "domain.h"
#include "main.h"
#include "user.h"

#define BUS1_INTERNAL_UID_INVALID ((unsigned int) -1)

static struct bus1_user *
bus1_user_new(struct bus1_domain_info *domain_info)
{
	struct bus1_user *u;

	u = kmalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return ERR_PTR(-ENOMEM);

	/*
	 * User objects must be released *entirely* before the parent domain
	 * is. As such, the domain pointer here is always valid and can be
	 * dereferenced without any protection.
	 */
	kref_init(&u->ref);
	u->uid = INVALID_UID;
	u->id = BUS1_INTERNAL_UID_INVALID;
	u->domain_info = domain_info;
	atomic_set(&u->fds_inflight, 0);

	return u;
}

static void bus1_user_free(struct kref *ref)
{
	struct bus1_user *user = container_of(ref, struct bus1_user, ref);

	WARN_ON(atomic_read(&user->fds_inflight));

	/* if already dropped, it's set to invalid */
	if (uid_valid(user->uid)) {
		mutex_lock(&user->domain_info->lock);
		if (uid_valid(user->uid)) /* check again underneath lock */
			idr_remove(&user->domain_info->user_idr,
				   __kuid_val(user->uid));
		mutex_unlock(&user->domain_info->lock);
	}

	/* drop the id from the ida if it was initialized */
	if (user->id != BUS1_INTERNAL_UID_INVALID)
		ida_simple_remove(&user->domain_info->user_ida, user->id);

	kfree_rcu(user, rcu);
}

/**
 * bus1_user_acquire_by_uid() - get a user object for a uid in the given domain
 * @domain:		domain of the user
 * @uid:		uid of the user
 *
 * Find and return the user object for the uid if it exists, otherwise create it
 * first. The caller is responsible to release their reference (and all derived
 * references) before the parent domain is deactivated!
 *
 * Return: A user object for the given uid, ERR_PTR on failure.
 */
struct bus1_user *
bus1_user_acquire_by_uid(struct bus1_domain *domain, kuid_t uid)
{
	struct bus1_user *user, *old_user;
	int r;

	WARN_ON(!uid_valid(uid));
	lockdep_assert_held(&domain->active);

	/* try to get the user without taking a lock */
	rcu_read_lock();
	user = idr_find(&domain->info->user_idr, __kuid_val(uid));
	if (user && !kref_get_unless_zero(&user->ref))
		user = NULL;
	rcu_read_unlock();
	if (user)
		return user;

	/* didn't exist, allocate a new one */
	user = bus1_user_new(domain->info);
	if (IS_ERR(user))
		return ERR_CAST(user);

	/*
	 * Allocate the smallest possible internal id for this user; used in
	 * arrays for accounting user quota in receiver pools.
	 */
	r = ida_simple_get(&domain->info->user_ida, 0, 0, GFP_KERNEL);
	if (r < 0)
		goto error;
	user->id = r;

	/*
	 * Now insert the new user object into the lookup tree. Note that
	 * someone might have raced us, in which case we need to switch over
	 * and drop our object. However, if the racing entry itself is already
	 * about to be destroyed again (ref-count is 0, cleanup handler is
	 * blocking on the domain-lock to drop the object), we rather replace
	 * the entry in the IDR with our own and mark the old one as removed.
	 *
	 * Note that we must set user->uid *before* the idr insertion, to make
	 * sure any rcu-lookup can properly read it, even before we drop the
	 * lock.
	 */
	mutex_lock(&domain->info->lock);
	user->uid = uid;
	old_user = idr_find(&domain->info->user_idr, __kuid_val(uid));
	if (likely(!old_user)) {
		r = idr_alloc(&domain->info->user_idr, user, __kuid_val(uid),
			      __kuid_val(uid) + 1, GFP_KERNEL);
		if (r < 0) {
			mutex_unlock(&domain->info->lock);
			user->uid = INVALID_UID; /* couldn't insert */
			goto error;
		}
	} else if (unlikely(!kref_get_unless_zero(&old_user->ref))) {
		idr_replace(&domain->info->user_idr, user, __kuid_val(uid));
		old_user->uid = INVALID_UID; /* mark old as removed */
		old_user = NULL;
	} else {
		user->uid = INVALID_UID; /* didn't insert, drop the marker */
	}
	mutex_unlock(&domain->info->lock);

	if (old_user) {
		bus1_user_release(user);
		user = old_user;
	}

	return user;

error:
	bus1_user_release(user);
	return ERR_PTR(r);
}

/**
 * bus1_user_acquire() - acquire reference
 * @user:	user to acquire, or NULL
 *
 * Acquire an additional reference to a user-object. The caller must already
 * own a reference. Furthermore, any acquired reference must be dropped before
 * the parent domain is dropped.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @user is returned.
 */
struct bus1_user *bus1_user_acquire(struct bus1_user *user)
{
	if (user)
		kref_get(&user->ref);
	return user;
}

/**
 * bus1_user_release() - release reference
 * @user:	user to release, or NULL
 *
 * Release a reference to a user-object. The caller must make sure to release
 * all their references before the parent domain is dropped.
 *
 * This function *might* lock the parent domain!
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_user *bus1_user_release(struct bus1_user *user)
{
	if (user)
		kref_put(&user->ref, bus1_user_free);
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
	quota->n_messages = 0;
	quota->allocated_size = 0;
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

/**
 * bus1_user_quota_charge() - try charging a user
 * @quota:		quota to operate on
 * @user:		user to charge
 * @pool_size:		pool size of the quota owner
 * @size:		size to charge
 * @n_fds:		number of FDs to charge
 *
 * This performs a quota charge on the passes quota object for the given user.
 * It first checks whether any quota is exceeded, and if not, it commits the
 * charge immediately.
 *
 * This charges for _one_ message with a size of @size bytes, carrying @n_fds
 * file descriptors as payload. The caller must provide the pool-size of the
 * target user via @pool_size (which us usually peer_info->pool.size on the
 * same peer as @quota is on).
 *
 * The caller must provide suitable locking.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_user_quota_charge(struct bus1_user_quota *quota,
			   struct bus1_user *user,
			   size_t pool_size,
			   size_t size,
			   size_t n_fds)
{
	struct bus1_user_stats *stats;
	size_t max;

	stats = bus1_user_quota_query(quota, user);
	if (IS_ERR(stats))
		return PTR_ERR(stats);

	WARN_ON(quota->n_messages > BUS1_MESSAGES_MAX);
	WARN_ON(stats->n_messages > quota->n_messages);
	WARN_ON(quota->allocated_size > pool_size);
	WARN_ON(stats->allocated_size > quota->allocated_size);

	/*
	 * A given user can have half of the total in-flight message
	 * budget that is not used by any other user.
	 */
	max = BUS1_MESSAGES_MAX - quota->n_messages + stats->n_messages;
	if (stats->n_messages + 1 > max / 2)
		return -EDQUOT;

	/*
	 * Similarly, a given user can use half of the total available
	 * in-flight pool size that is not used by any other user.
	 */
	max = pool_size - quota->allocated_size + stats->allocated_size;
	if (stats->allocated_size + size > max / 2)
		return -EDQUOT;

	/*
	 * Unlike the other quotas, file-descriptors have global per-user
	 * limits, just like UDS does it. Preferably, we would use
	 * user_struct->unix_inflight, but it is not accessible by modules.
	 * Hence, we have our own per-user counter.
	 * Note that this check is racy. However, we couldn't care less.. There
	 * is no reason to enforce it strictly. We'd want something like
	 * atomic_add_unless_greater().
	 */
	if (atomic_read(&user->fds_inflight) + n_fds > rlimit(RLIMIT_NOFILE))
		return -ETOOMANYREFS;

	stats->allocated_size += size;
	stats->n_messages += 1;
	atomic_add(n_fds, &user->fds_inflight);
	return 0;
}

/**
 * bus1_user_quota_discharge() - discharge a user
 * @quota:		quota to operate on
 * @user:		user to discharge
 * @size:		size to discharge
 * @n_fds:		number of FDs to discharge
 *
 * This reverts a single charge done via bus1_user_quota_charge(). It discharges
 * a single message with a slice size of @size and @n_fds file-descriptors.
 */
void bus1_user_quota_discharge(struct bus1_user_quota *quota,
			       struct bus1_user *user,
			       size_t size,
			       size_t n_fds)
{
	struct bus1_user_stats *stats;

	stats = bus1_user_quota_query(quota, user);
	if (WARN_ON(IS_ERR_OR_NULL(stats)))
		return;

	WARN_ON(size > stats->allocated_size);
	WARN_ON(stats->n_messages < 1);
	WARN_ON(n_fds > atomic_read(&user->fds_inflight));

	stats->allocated_size -= size;
	stats->n_messages -= 1;
	atomic_sub(n_fds, &user->fds_inflight);
}
