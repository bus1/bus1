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
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include "domain.h"
#include "user.h"

static struct bus1_user *bus1_user_new(struct bus1_domain_info *domain_info,
				       kuid_t uid)
{
	struct bus1_user *u;

	if (WARN_ON(!uid_valid(uid)))
		return ERR_PTR(-EINVAL);

	u = kmalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return ERR_PTR(-ENOMEM);

	kref_init(&u->ref);
	/*
	 * in order for this pointer to always be valid, we rely on the user
	 * object to be released before its parent is freed
	 */
	u->domain_info = domain_info;
	u->uid = uid;
	u->id = 0;

	return u;
}

static struct bus1_user *bus1_user_get(struct bus1_domain_info *domain_info,
				       kuid_t uid)
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
 * first.
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
	 * try to allocate some space in the ida to avoid doing so under the
	 * lock. this is best effort only, so ignore any errors.
	 */
	(void) ida_pre_get(&domain->info->user_ida, GFP_KERNEL);

	mutex_lock(&domain->info->lock);
	/*
	 * someone else might have raced us outside the lock, so check if the
	 * user still does not exist
	 */
	old_user = idr_find(&domain->info->user_idr, __kuid_val(uid));
	if (likely(!old_user)) {
		/*
		 * the user still does not exist, so link in the newly created
		 * one
		 */
		r = idr_alloc(&domain->info->user_idr, new_user,
			      __kuid_val(uid), __kuid_val(uid) + 1, GFP_KERNEL);
		if (r < 0)
			goto exit;
	} else {
		/*
		 * there was a race and a new user has already created, check if
		 * we can use it
		 */
		if (likely(kref_get_unless_zero(&old_user->ref))) {
			/*
			 * the preexisting user is not being destroyed so use
			 * that and let the one we allocated be discarded later
			 * on
			 */
			user = old_user;
			goto exit;
		} else {
			/*
			 * the old user is already being destroyd, so simply
			 * replace it in the idr with the newly allocated one
			 */
			idr_replace(&domain->info->user_idr, new_user,
				    __kuid_val(uid));
			old_user->uid = INVALID_UID; /* mark old as removed */
		}
	}

	/*
	 * allocate the smallest possible internal id for this user; used in
	 * arrays for accounting user quota in receiver pools.
	 */
	r = ida_simple_get(&domain->info->user_ida, 1, 0, GFP_KERNEL);
	if (r < 0)
		goto exit;
	else
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
	if (uid_valid(user->uid))
		/* the user was not already replaced by another in the idr */
		idr_remove(&user->domain_info->user_idr,
			   __kuid_val(user->uid));
	mutex_unlock(&user->domain_info->lock);

	kfree_rcu(user, rcu);
}

/**
 * bus1_user_release() - release the reference to the user object from the
 *			 domain
 * @user:	User
 *
 * The user object must be released before the corresponding domain is freed,
 * which in practice means that it should be released before its parent object
 * is freed.
 *
 * Return: NULL
 */
struct bus1_user *bus1_user_release(struct bus1_user *user)
{
	if (user)
		kref_put(&user->ref, bus1_user_free);

	return NULL;
}
