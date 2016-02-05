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
#include "user.h"

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
	u->id = 0;

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
 * bus1_user_acquire() - get a user object for a uid in the given domain
 * @domain:		domain of the user
 * @uid:		uid of the user
 *
 * Find and return the user object for the uid if it exists, otherwise create it
 * first. The caller is responsible to release their reference (and all derived
 * references) before the parent domain is deactivated!
 *
 * Return: A user object for the given uid, ERR_PTR on failure.
 */
struct bus1_user *bus1_user_acquire(struct bus1_domain *domain, kuid_t uid)
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
	 * Try to allocate some space in the ida to avoid doing so under the
	 * lock. This is best effort only, so ignore any errors.
	 */
	ida_pre_get(&domain->info->user_ida, GFP_KERNEL);

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

	/* get a sparse identifier for this user */
	r = ida_simple_get(&domain->info->user_ida, 1, 0, GFP_KERNEL);
	if (r < 0)
		goto exit;

	new_user->id = r;
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

	mutex_lock(&user->domain_info->lock);
	/* drop the id from the ida, initialized ids are >= 0 */
	ida_simple_remove(&user->domain_info->user_ida, user->id);
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
