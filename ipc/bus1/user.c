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
#include "pool.h"
#include "queue.h"
#include "user.h"

#define BUS1_INTERNAL_UID_INVALID ((unsigned int) -1)

static struct bus1_user *
bus1_user_new(struct bus1_domain_info *domain_info, kuid_t uid)
{
	struct bus1_user *u;

	if (WARN_ON(!uid_valid(uid)))
		return ERR_PTR(-EINVAL);

	u = kmalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return ERR_PTR(-ENOMEM);

	kref_init(&u->ref);
	/*
	 * User objects must be released *entirely* before the parent domain
	 * is. As such, the domain pointer here is always valid and can be
	 * dereferenced without any protection.
	 */
	u->domain_info = domain_info;
	u->uid = uid;
	u->id = BUS1_INTERNAL_UID_INVALID;

	return u;
}

static struct bus1_user *
bus1_user_get(struct bus1_domain_info *domain_info, kuid_t uid)
{
	struct bus1_user *user;

	rcu_read_lock();
	user = idr_find(&domain_info->user_idr, __kuid_val(uid));
	if (user && !kref_get_unless_zero(&user->ref))
		/* the user is about to be destroyed, ignore it */
		user = NULL;
	rcu_read_unlock();

	return user;
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
	struct bus1_user *user, *old_user, *new_user;
	int r = 0;

	WARN_ON(!uid_valid(uid));

	lockdep_assert_held(&domain->active);

	/* try to get the user without taking a lock */
	user = bus1_user_get(domain->info, uid);
	if (user)
		return user;

	/* didn't exist, allocate a new one */
	new_user = bus1_user_new(domain->info, uid);
	if (IS_ERR(new_user))
		return new_user;

	/*
	 * Allocate the smallest possible internal id for this user; used in
	 * arrays for accounting user quota in receiver pools.
	 */
	r = ida_simple_get(&domain->info->user_ida, 0, 0, GFP_KERNEL);
	if (r < 0)
		goto exit;

	new_user->id = r;

	mutex_lock(&domain->info->lock);
	/*
	 * Someone else might have raced us outside the lock, so check if the
	 * user still does not exist.
	 */
	old_user = idr_find(&domain->info->user_idr, __kuid_val(uid));
	if (likely(!old_user)) {
		/* user does not exist, link the newly created one */
		r = idr_alloc(&domain->info->user_idr, new_user,
			      __kuid_val(uid), __kuid_val(uid) + 1, GFP_KERNEL);
		if (r < 0)
			goto exit;
	} else {
		/* another allocation raced us, try re-using that one */
		if (likely(kref_get_unless_zero(&old_user->ref))) {
			user = old_user;
			goto exit;
		} else {
			/* the other one is getting destroyed, replace it */
			idr_replace(&domain->info->user_idr, new_user,
				    __kuid_val(uid));
			old_user->uid = INVALID_UID; /* mark old as removed */
		}
	}

	user = new_user;
	new_user = NULL;

exit:
	mutex_unlock(&domain->info->lock);
	bus1_user_release(new_user);
	if (r < 0)
		return ERR_PTR(r);
	return user;
}

static void bus1_user_free(struct kref *ref)
{
	struct bus1_user *user = container_of(ref, struct bus1_user, ref);

	/* drop the id from the ida if it was initialized */
	if (user->id != BUS1_INTERNAL_UID_INVALID)
		ida_simple_remove(&user->domain_info->user_ida, user->id);

	mutex_lock(&user->domain_info->lock);
	if (uid_valid(user->uid)) /* if already dropped, it's set to invalid */
		idr_remove(&user->domain_info->user_idr,
			   __kuid_val(user->uid));
	mutex_unlock(&user->domain_info->lock);

	kfree_rcu(user, rcu);
}

/**
 * bus1_user_release() - release the reference to the user object from the
 *			 domain
 * @user:	user to release, or NULL
 *
 * The user object must be released before the corresponding domain is freed,
 * which in practice means that it should be released before its parent object
 * is freed.
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
 * bus1_user_acquire() - acquire a reference to the user
 * @user:	User
 *
 * Return: @user
 */
struct bus1_user *bus1_user_acquire(struct bus1_user *user)
{
	if (user)
		kref_get(&user->ref);

	return user;
}

int bus1_user_quotas_ensure_allocated(struct bus1_user_quota **quotasp,
				      size_t *n_quotasp, unsigned int id)
{
	struct bus1_user_quota *quotas;
	unsigned int n_quotas;

	if (id < *n_quotasp)
		return 0;

	/*
	 * Align the number of users and allocate a few extra, but protect
	 * against overflows.
	 */
	n_quotas = max(ALIGN(id, 8) + 8, id);
	quotas = *quotasp;

	quotas = krealloc(quotas,
			  n_quotas * sizeof(struct bus1_user_quota),
			  GFP_KERNEL | __GFP_ZERO);
	if (!quotas)
		return -ENOMEM;

	*quotasp = quotas;
	*n_quotasp = n_quotas;

	return 0;
}

void bus1_user_quotas_destroy(struct bus1_user_quota **quotasp,
			      size_t *n_quotasp)
{
	if (!*quotasp)
		return;

	kfree(*quotasp);
	*quotasp = NULL;

	if (*n_quotasp)
		*n_quotasp = 0;
}

int bus1_user_quota_check(struct bus1_user_quota *quota, size_t size,
			  struct bus1_pool *pool,
			  struct bus1_queue *queue)
{
	/* we can check a quota without allocating it first */
	u32 allocated_size;
	u16 n_messages;

	if (quota) {
		allocated_size = quota->allocated_size;
		n_messages = quota->n_messages;
	} else {
		allocated_size = 0;
		n_messages = 0;
	}

	/*
	 * The max queue size is not a hard limit, as there is a race between
	 * checking the quota and queuing the messages. However, it is not
	 * important that this is strictly enforced, so we don't care.
	 * WARN_ON(queue->n_messages > BUS1_QUEUE_MESSAGES_MAX);
	 */
	WARN_ON(n_messages > queue->n_messages);

	/*
	 * A given user can have half of the total in-flight message
	 * budget that is not used by any other user.
	 */
	if (n_messages + 1 >
	    (BUS1_QUEUE_MESSAGES_MAX - queue->n_messages + n_messages) / 2)
		return -ENOBUFS;

	WARN_ON(pool->allocated_size > pool->size);
	WARN_ON(allocated_size > pool->allocated_size);

	/*
	 * Similarly, a given user can use half of the total available
	 * in-flight pool size that is not used by any other user.
	 */
	if (allocated_size + size >
	    (pool->size - pool->allocated_size + allocated_size) / 2)
		return -ENOBUFS;

	return 0;
}
