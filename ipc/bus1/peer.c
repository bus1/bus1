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
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "domain.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "user.h"
#include "util.h"

struct bus1_peer_track {
	struct kref ref;			/* reference counter */
	struct bus1_peer __rcu *tracker;	/* points to the tracker */
	struct bus1_peer __rcu *trackee;	/* points to the trackee */
	struct rb_node rb_tracker;		/* link into @tracker */
	struct list_head link_trackee;		/* link into @trackee */
};

struct bus1_peer_name {
	union {
		struct rcu_head rcu;
		struct bus1_peer_name *next;
	};
	struct bus1_peer *peer;
	struct rb_node rb;
	char name[];
};

static void bus1_peer_track_free(struct kref *ref)
{
	/*
	 * The track object is never cleared and might have stale rb/list
	 * entries at any time. Don't look at them here, just plain free the
	 * object. No rcu. No warnings. Just get rid of it.
	 */
	kfree(container_of(ref, struct bus1_peer_track, ref));
}

static void bus1_peer_track_no_free(struct kref *ref)
{
	/* used if we know we hold more than 1 reference */
	WARN(1, "Track object freed unexpectedly");
}

static struct bus1_peer *
bus1_peer_info_pop_tracker(struct bus1_peer_info *trackee_info)
{
	struct bus1_peer_info *tracker_info;
	struct bus1_peer_track *track;
	struct bus1_peer *tracker;

	/*
	 * This unlinks a single tracker of @trackee_info, pins the owning peer
	 * and returns a pointer to the pinned peer. Call this repeatedly to
	 * drain all trackers, but make sure the peer is disconnected and no
	 * new trackers are installed.
	 *
	 * This is usually used to instantiate a peer-disconnect notification
	 * on each tracker, before destroying a peer.
	 *
	 * This implementation simply locks the peer and looks at the first
	 * tracker it can get its hands on. We unlink the local side and try to
	 * pin the remote side. If this fails, we know the remote will clean up
	 * this track object, so we simply skip it and continue with the next
	 * one. In case we can pin the remote entry, we unlink the object from
	 * it, drop the last reference and return the pinned peer to the
	 * caller.
	 */

	mutex_lock(&trackee_info->lock);
	while ((track = list_first_entry_or_null(&trackee_info->list_trackers,
						 struct bus1_peer_track,
						 link_trackee))) {
		/* unlink from protected trackee */
		rcu_assign_pointer(track->trackee, NULL);
		list_del(&track->link_trackee);

		/* try to pin tracker (RCU protects runtime of acquisition) */
		rcu_read_lock();
		tracker = bus1_peer_acquire(rcu_dereference(track->tracker));
		rcu_read_unlock();

		/*
		 * Remote tracker is pinned and local link is cleared. Unlock
		 * the peer, then lock the tracker and drop their link. The
		 * local ref is hold to guarantee the track object is not
		 * dropped. As a last step, drop the local reference and return
		 * the pinned tracker to the caller.
		 *
		 * Note that an UNTRACK operation of @tracker might race us. We
		 * don't care, though. We just pretend it happened after we
		 * popped the tracker.
		 */
		if (tracker) {
			mutex_unlock(&trackee_info->lock);

			tracker_info = bus1_peer_dereference(tracker);
			mutex_lock(&tracker_info->lock);
			if (rcu_access_pointer(track->tracker)) {
				rcu_assign_pointer(track->tracker, NULL);
				rb_erase(&track->rb_tracker,
					 &tracker_info->map_trackees);
				kref_put(&track->ref, bus1_peer_track_no_free);
			}
			mutex_unlock(&tracker_info->lock);

			kref_put(&track->ref, bus1_peer_track_free);
			return tracker;
		}

		/*
		 * We cannot pin the tracker, it either is already gone or it
		 * is about to go. Either way, we don't have to care for their
		 * reference, it is enough to drop ours and continue.
		 */
		kref_put(&track->ref, bus1_peer_track_free);
	}
	mutex_unlock(&trackee_info->lock);

	return NULL;
}

static void bus1_peer_info_notify(struct bus1_peer_info *peer_info)
{
	struct bus1_peer *tracker;

	/*
	 * XXX: Notifications are not implemented, yet. This is a stub that
	 * just flushes the trackees, but never sends any message.
	 */

	while ((tracker = bus1_peer_info_pop_tracker(peer_info)))
		bus1_peer_release(tracker);
}

static void bus1_peer_info_flush_trackees(struct bus1_peer_info *peer_info,
					  struct rb_root *root)
{
	struct bus1_peer_track *track, *t;

	/*
	 * This flushes all tracks that a peer has set up. The peer must be
	 * locked by the caller. We then *pretend* to unlink all tracks. We do
	 * this by setting the tracker to NULL on all tracks, but retain the
	 * reference and rbtree. We also clear the rbtree to NULL. It now looks
	 * like the peer has no tracks, and all previous tracks are
	 * half-unlinked with an additional ref holder.
	 *
	 * This temporary tree is then handed back to the caller, which can
	 * unlock the peer and then safely finish the tracks without having to
	 * keep the peer locked. See bus1_peer_info_finish_trackees().
	 */

	lockdep_assert_held(&peer_info->lock);

	*root = peer_info->map_trackees;
	peer_info->map_trackees = RB_ROOT;

	rbtree_postorder_for_each_entry_safe(track, t, root, rb_tracker)
		rcu_assign_pointer(track->tracker, NULL);
}

static void bus1_peer_info_finish_trackees(struct rb_root *root)
{
	struct bus1_peer_track *track, *t;
	struct bus1_peer_info *trackee_info;
	struct bus1_peer *trackee;

	/*
	 * This is the tail of bus1_peer_info_flush_trackees(). It takes a tree
	 * of unlinked tracks and tries dropping them from their remote
	 * trackee. There is no need to hold any local lock, as the tree itself
	 * is accessible exclusively by this context (since it was already
	 * unlinked before).
	 */

	rbtree_postorder_for_each_entry_safe(track, t, root, rb_tracker) {
		/* try to pin trackee (RCU protects runtime of acquisition) */
		rcu_read_lock();
		trackee = bus1_peer_acquire(rcu_dereference(track->trackee));
		rcu_read_unlock();

		if (trackee) {
			trackee_info = bus1_peer_dereference(trackee);
			mutex_lock(&trackee_info->lock);
			if (rcu_access_pointer(track->trackee)) {
				rcu_assign_pointer(track->trackee, NULL);
				list_del(&track->link_trackee);
				kref_put(&track->ref, bus1_peer_track_no_free);
			}
			mutex_unlock(&trackee_info->lock);
			bus1_peer_release(trackee);
		}

		kref_put(&track->ref, bus1_peer_track_free);
	}
}

static struct bus1_peer_info *
bus1_peer_info_free(struct bus1_peer_info *peer_info)
{
	struct rb_root trackees;

	if (!peer_info)
		return NULL;

	WARN_ON(peer_info->user);

	mutex_lock(&peer_info->lock); /* lock peer to make lockdep happy */
	bus1_queue_flush(&peer_info->queue, &peer_info->pool, 0);
	bus1_peer_info_flush_trackees(peer_info, &trackees);
	mutex_unlock(&peer_info->lock);

	bus1_peer_info_finish_trackees(&trackees);
	bus1_peer_info_notify(peer_info);

	bus1_queue_destroy(&peer_info->queue);
	bus1_pool_destroy(&peer_info->pool);

	/*
	 * Make sure the object is freed in a delayed-manner. Some
	 * embedded members (like the queue) must be accessible for an entire
	 * rcu read-side critical section.
	 */
	kfree_rcu(peer_info, rcu);

	return NULL;
}

static struct bus1_peer_info *
bus1_peer_info_new(struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;
	int r;

	if (unlikely(param->pool_size == 0 ||
		     !IS_ALIGNED(param->pool_size, PAGE_SIZE)))
		return ERR_PTR(-EINVAL);

	peer_info = kmalloc(sizeof(*peer_info), GFP_KERNEL);
	if (!peer_info)
		return ERR_PTR(-ENOMEM);

	mutex_init(&peer_info->lock);
	peer_info->pool = BUS1_POOL_NULL;
	bus1_queue_init_for_peer(&peer_info->queue, peer_info);
	peer_info->user = NULL;
	peer_info->map_trackees = RB_ROOT;
	INIT_LIST_HEAD(&peer_info->list_trackers);

	r = bus1_pool_create_for_peer(&peer_info->pool, peer_info,
				      param->pool_size);
	if (r < 0)
		goto error;

	return peer_info;

error:
	bus1_peer_info_free(peer_info);
	return ERR_PTR(r);
}

static void bus1_peer_info_reset(struct bus1_peer_info *peer_info, u64 id)
{
	struct rb_root trackees;

	mutex_lock(&peer_info->lock);
	bus1_queue_flush(&peer_info->queue, &peer_info->pool, id);
	bus1_pool_flush(&peer_info->pool);
	bus1_peer_info_flush_trackees(peer_info, &trackees);
	mutex_unlock(&peer_info->lock);

	bus1_peer_info_finish_trackees(&trackees);
	bus1_peer_info_notify(peer_info);
}

static struct bus1_peer_name *
bus1_peer_name_new(const char *name, struct bus1_peer *peer)
{
	struct bus1_peer_name *peer_name;
	size_t namelen;

	if (WARN_ON(!peer))
		return ERR_PTR(-EINVAL);

	namelen = strlen(name) + 1;
	if (namelen < 2 || namelen > BUS1_NAME_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	peer_name = kmalloc(sizeof(*peer_name) + namelen, GFP_KERNEL);
	if (!peer_name)
		return ERR_PTR(-ENOMEM);

	peer_name->next = NULL;
	peer_name->peer = peer;
	RB_CLEAR_NODE(&peer_name->rb);
	memcpy(peer_name->name, name, namelen);

	return peer_name;
}

static struct bus1_peer_name *
bus1_peer_name_free(struct bus1_peer_name *peer_name)
{
	if (!peer_name)
		return NULL;

	WARN_ON(!RB_EMPTY_NODE(&peer_name->rb));
	kfree_rcu(peer_name, rcu);

	return NULL;
}

static int bus1_peer_name_add(struct bus1_peer_name *peer_name,
			      struct bus1_domain *domain)
{
	struct rb_node *prev, **slot;
	struct bus1_peer_name *iter;
	int v;

	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);

	if (WARN_ON(!RB_EMPTY_NODE(&peer_name->rb)))
		return -EINVAL;

	/* find rb-tree entry and check for possible duplicates first */
	slot = &domain->map_names.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = container_of(prev, struct bus1_peer_name, rb);
		v = strcmp(peer_name->name, iter->name);
		if (!v)
			return -EISNAM;
		else if (v < 0)
			slot = &prev->rb_left;
		else /* if (v > 0) */
			slot = &prev->rb_right;
	}

	/* insert into tree */
	rb_link_node_rcu(&peer_name->rb, prev, slot);
	rb_insert_color(&peer_name->rb, &domain->map_names);

	++domain->n_names;
	return 0;
}

static void bus1_peer_name_remove(struct bus1_peer_name *peer_name,
				  struct bus1_domain *domain)
{
	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);

	if (RB_EMPTY_NODE(&peer_name->rb))
		return;

	rb_erase(&peer_name->rb, &domain->map_names);
	RB_CLEAR_NODE(&peer_name->rb);

	--domain->n_names;
}

/**
 * bus1_peer_new() - allocate new peer
 *
 * Allocate a new peer handle. The handle is *not* activated, nor linked to any
 * domain. The caller owns the only pointer to the new peer.
 *
 * Return: Pointer to peer, ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(void)
{
	struct bus1_peer *peer;

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	init_rwsem(&peer->rwlock);
	init_waitqueue_head(&peer->waitq);
	bus1_active_init(&peer->active);
	rcu_assign_pointer(peer->info, NULL);
	peer->names = NULL;
	RB_CLEAR_NODE(&peer->rb);
	peer->id = 0;

	return peer;
}

/**
 * bus1_peer_free() - destroy peer
 * @peer:	peer to destroy, or NULL
 *
 * Destroy a peer object that was previously allocated via bus1_peer_new(). If
 * the peer object was activated, then the caller must make sure it was
 * properly torn down before destroying it.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	/* peer->rb might be stray */
	WARN_ON(peer->names);
	WARN_ON(rcu_access_pointer(peer->info));
	bus1_active_destroy(&peer->active);
	kfree_rcu(peer, rcu);

	return NULL;
}

struct bus1_peer_cleanup_context {
	struct bus1_domain *domain;
	struct bus1_peer_info *stale_info;
};

static void bus1_peer_cleanup(struct bus1_peer *peer,
			      struct bus1_peer_cleanup_context *ctx,
			      bool drop_from_tree)
{
	struct bus1_domain *domain = ctx->domain;
	struct bus1_peer_name *peer_name;
	struct bus1_peer_info *peer_info;

	/*
	 * This function is called by bus1_active_cleanup(), once all active
	 * references to the handle are drained. In that case, we know that
	 * no-one can hold a pointer to the peer, anymore. Hence, we can simply
	 * drop all the peer information and destroy the peer.
	 *
	 * During domain teardown, we avoid dropping peers from the tree, so we
	 * can safely iterate the tree and reset it afterwards.
	 *
	 * If this released the peer, the peer information object is returned
	 * to the caller via the passed in context. The caller must destroy it
	 * by calling bus1_peer_info_free(). We skip this step here, to allow
	 * the caller to drop locks before freeing the peer, and thus reducing
	 * lock contention.
	 * The caller really ought to initialize @ctx->stale_info to NULL, so
	 * it can check whether this call actually released the peer or not.
	 */

	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);
	WARN_ON(ctx->stale_info);

	peer_info = rcu_dereference_protected(peer->info,
					      lockdep_is_held(&domain->lock));
	if (peer_info) {
		while ((peer_name = peer->names)) {
			peer->names = peer->names->next;
			bus1_peer_name_remove(peer_name, domain);
			bus1_peer_name_free(peer_name);
		}

		if (drop_from_tree)
			rb_erase(&peer->rb, &domain->map_peers);

		--domain->n_peers;

		/*
		 * Reset @peer->info so any racing rcu-call will get NULL
		 * before the peer is released via kfree_rcu().
		 *
		 * Instead of calling into bus1_peer_info_free(), return the
		 * stale peer via the context to the caller. The object is
		 * fully unlinked (except for harmless rcu queries), so the
		 * caller can drop their locks before calling into
		 * bus1_peer_info_free().
		 */
		rcu_assign_pointer(peer->info, NULL);
		ctx->stale_info = peer_info;
	} else {
		WARN_ON(peer->names);
	}
}

static void bus1_peer_cleanup_runtime(struct bus1_active *active,
				      void *userdata)
{
	struct bus1_peer *peer = container_of(active, struct bus1_peer,
					      active);

	return bus1_peer_cleanup(peer, userdata, true);
}

int bus1_peer_teardown(struct bus1_peer *peer, struct bus1_domain *domain)
{
	struct bus1_peer_cleanup_context ctx = { .domain = domain, };
	struct bus1_peer_info *peer_info;
	int r;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	/* deactivate and wait for any outstanding operations */
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	/*
	 * We must not sleep on the peer->waitq, it could deadlock
	 * since we already hold the domain-lock. However, luckily all
	 * peer-releases are locked against the domain, so we wouldn't
	 * gain anything by passing the waitq in. Pass NULL instead.
	 */
	mutex_lock(&domain->lock);
	write_seqcount_begin(&domain->seqcount);

	peer_info = rcu_dereference_protected(peer->info,
					      lockdep_is_held(&domain->lock));
	if (peer_info)
		peer_info->user = bus1_user_release(peer_info->user);

	if (bus1_active_cleanup(&peer->active, NULL,
				bus1_peer_cleanup_runtime, &ctx))
		r = 0;
	else
		r = -ESHUTDOWN;
	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);

	up_write(&peer->rwlock);

	/*
	 * bus1_peer_cleanup() returns the now stale peer pointer via the
	 * context (but only if it really released the peer, otherwise it is
	 * NULL). It allows us to drop the locks before calling into
	 * bus1_peer_info_free(). This is not strictly necessary, but reduces
	 * lock-contention on @domain->lock.
	 */
	bus1_peer_info_free(ctx.stale_info);

	return r;
}

static void bus1_peer_cleanup_domain(struct bus1_active *active,
				     void *userdata)
{
	struct bus1_peer *peer = container_of(active, struct bus1_peer,
					      active);

	bus1_peer_cleanup(peer, userdata, false);
}

/**
 * bus1_peer_teardown_domain() - tear down peer
 * @peer:	peer to tear down
 * @domain:	parent domain
 *
 * This is similar to bus1_peer_teardown(), but is modified to be called during
 * domain teardown. The domain is responsible to deactivate and drain a peer
 * before calling into this. Furthermore, the domain itself must be deactivated
 * and drained already.
 *
 * This function simply cleans up the peer object and releases associated
 * resources. However, this function does *NOT* remove the peer from the
 * peer-map. This allows the caller to safely iterate the peer map and call
 * this helper on all peers.
 *
 * The caller is responsible to reset the peer-map afterwards.
 *
 * The caller must hold the domain lock and seqlock.
 *
 * This function can be called multiple times just fine. Anything but the first
 * call will be a no-op.
 */
void bus1_peer_teardown_domain(struct bus1_peer *peer,
			       struct bus1_domain *domain)
{
	struct bus1_peer_cleanup_context ctx = { .domain = domain, };
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);

	peer_info = rcu_dereference_protected(peer->info,
					      lockdep_is_held(&domain->lock));
	if (peer_info)
		peer_info->user = bus1_user_release(peer_info->user);

	/*
	 * We must not sleep on the peer->waitq, it could deadlock
	 * since we already hold the domain-lock. However, luckily all
	 * peer-releases are locked against the domain, so we wouldn't
	 * gain anything by passing the waitq in.
	 *
	 * We use a custom cleanup-callback which does the normal peer
	 * cleanup, but leaves the rb-tree untouched. This simplifies
	 * our iterator, as long as we properly reset the tree
	 * afterwards.
	 */
	bus1_active_cleanup(&peer->active, NULL,
			    bus1_peer_cleanup_domain, &ctx);

	/*
	 * bus1_peer_cleanup() returns the now stale peer pointer via the
	 * context (but only if it really released the peer, otherwise it is
	 * NULL). It allows us to drop the locks before calling into
	 * bus1_peer_info_free(). However, we're called from domain teardown,
	 * so lock contention doesn't matter, so release it without dropping
	 * any lock.
	 */
	bus1_peer_info_free(ctx.stale_info);
}

/**
 * bus1_peer_acquire() - acquire active reference to peer
 * @peer:	peer to operate on, or NULL
 *
 * Acquire a new active reference to the given peer. If the peer was not
 * activated yet, or if it was already deactivated, this will fail.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: Pointer to peer, NULL on failure.
 */
struct bus1_peer *bus1_peer_acquire(struct bus1_peer *peer)
{
	if (peer && bus1_active_acquire(&peer->active))
		return peer;
	return NULL;
}

/**
 * bus1_peer_acquire_raw_by_id() - acquire peer by id
 * @domain:		domain to search
 * @id:			id to look for
 *
 * Find a peer handle that is registered under the given id and domain. If
 * found, acquire an active reference and return the handle. If not found, NULL
 * is returned.
 *
 * This always acquires a raw active reference. That is, you must release it
 * via bus1_peer_release_raw()! As such, no lockdep annotations are provided.
 *
 * Return: Active reference to matching handle, or NULL.
 */
struct bus1_peer *bus1_peer_acquire_raw_by_id(struct bus1_domain *domain,
					      u64 id)
{
	struct bus1_peer *peer, *res = NULL;
	struct rb_node *n;
	unsigned seq;

	/* first try without waiting for any writers */
	seq = raw_seqcount_begin(&domain->seqcount);
	do {
		rcu_read_lock();
		n = rcu_dereference(domain->map_peers.rb_node);
		while (n) {
			peer = container_of(n, struct bus1_peer, rb);
			if (id == peer->id) {
				if (bus1_active_acquire_raw(&peer->active))
					res = peer;
				break;
			} else if (id < peer->id) {
				n = rcu_dereference(n->rb_left);
			} else /* if (id > peer->id) */ {
				n = rcu_dereference(n->rb_right);
			}
		}
		rcu_read_unlock();
	} while (!res &&
		 read_seqcount_retry(&domain->seqcount, seq) &&
		 ((seq = read_seqcount_begin(&domain->seqcount)), true));

	return res;
}

/**
 * bus1_peer_release() - release an active reference
 * @peer:	handle to release, or NULL
 *
 * This releases an active reference to a peer, acquired previously via one
 * of the lookup functions.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_release(struct bus1_peer *peer)
{
	if (peer)
		bus1_active_release(&peer->active, &peer->waitq);
	return NULL;
}

/**
 * bus1_peer_release_raw() - release an active reference
 * @peer:	handle to release, or NULL
 *
 * See bus1_peer_release() for details. This releases a raw reference, rather
 * than a normal reference (skips lockdep annotations).
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_release_raw(struct bus1_peer *peer)
{
	if (peer)
		bus1_active_release_raw(&peer->active, &peer->waitq);
	return NULL;
}

/**
 * bus1_peer_dereference() - dereference a peer handle
 * @peer:	handle to dereference
 *
 * Dereference a peer handle to get access to the underlying peer object. This
 * function simply returns the pointer to the linked peer information object,
 * which then can be accessed directly by the caller. The caller must hold an
 * active reference to the handle, and retain it as long as the peer object is
 * used.
 *
 * Note: If you weren't called through this handle, but rather retrieved it via
 *       other means (eg., domain lookup), you must be aware that this handle
 *       might be reset at any time. Hence, any operation you perform on the
 *       handle must be tagged by the actual peer ID (which you should have
 *       retrieved via the same means as the handle itself).
 *       If the peer is reset midway through your operation, it gets a new ID,
 *       notifies any peer that tracked it, and automatically discards any
 *       operation that was tagged with an old ID (or, if the operation wasn't
 *       finished, it will be discarded later on). A reset is a lossy operation
 *       so any pending operation is discarded silently. The origin of the
 *       operation thus gets the impression that it succeeded (and should be
 *       tracking the peer to get notified about the reset, if interested).
 *
 * Return: Pointer to the underlying peer information object is returned.
 */
struct bus1_peer_info *bus1_peer_dereference(struct bus1_peer *peer)
{
	/*
	 * Preferably, we'd use lockdep_is_held(&peer->active), but this will
	 * fail if the caller uses raw active references. Hence, lets just make
	 * sure there is at least a single reference there.
	 */
	return rcu_dereference_protected(peer->info,
				!bus1_active_is_drained(&peer->active));
}

/*
 * Check if the string is a name of the peer.
 *
 * Return: -EREMCHG if it is not, 0 if it is but is not the last name, and the
 * number of names the peer has otherwise.
 */
static ssize_t bus1_peer_name_check(struct bus1_peer *peer, const char *name)
{
	struct bus1_peer_name *peer_name;
	size_t n_names = 0;

	lockdep_assert_held(&peer->rwlock);

	for (peer_name = peer->names; peer_name; peer_name = peer_name->next) {
		++n_names;

		if (strcmp(name, peer_name->name) == 0) {
			if (peer_name->next)
				return 0;
			else
				return n_names;
		}
	}

	return -EREMCHG;
}

/*
 * Check if a nulstr contains exactly the names of the peer.
 *
 * Return: 0 if it does, -EREMCHG if it does not or -EMSGSIZE if it is
 * malformed.
 */
static int bus1_peer_names_check(struct bus1_peer *peer, const char *names,
				 size_t names_len)
{
	size_t n, n_names = 0, n_names_old = 0;
	ssize_t r;

	lockdep_assert_held(&peer->rwlock);

	if (names_len == 0 && peer->names)
		return -EREMCHG;

	while (names_len > 0) {
		n = strnlen(names, names_len);
		if (n == 0 || n == names_len)
			return -EMSGSIZE;

		r = bus1_peer_name_check(peer, names);
		if (r < 0)
			return r;
		if (r > 0)
			n_names_old = r;

		names += n + 1;
		names_len -= n + 1;
		++n_names;
	}

	if (n_names != n_names_old)
		return -EREMCHG;

	return 0;
}

static int bus1_peer_connect_new(struct bus1_peer *peer,
				 struct bus1_domain *domain,
				 kuid_t uid,
				 struct bus1_cmd_connect *param)
{
	struct bus1_peer_name *peer_name, *names = NULL;
	struct bus1_peer_info *peer_info;
	struct rb_node *last;
	size_t n, remaining;
	const char *name;
	int r;

	/*
	 * Connect a new peer. We first allocate the peer object, then
	 * lock the whole domain and link the names and the peer
	 * itself. If either fails, revert everything we did so far and
	 * bail out.
	 */

	lockdep_assert_held(&domain->active);
	lockdep_assert_held(&peer->rwlock);

	/* cannot connect a peer that is already connected */
	if (!bus1_active_is_new(&peer->active)) {
		struct bus1_peer_info *peer_info;

		/*
		 * If the peer is already connected, we return -EISCONN if the
		 * passed in parameters match, or -EREMCHG if they do not (but
		 * are otherwise valid).
		 */

		/*
		 * We hold a domain-reference and peer-lock, the caller already
		 * verified we're not disconnected. Barriers guarantee that the
		 * peer is accessible, and both the domain teardown and
		 * peer-disconnect have to wait for us to finish. However, to
		 * be safe, check for NULL anyway.
		 */
		peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&domain->active) &&
					lockdep_is_held(&peer->rwlock));
		if (WARN_ON(!peer_info))
			return -ESHUTDOWN;

		if (param->pool_size != peer_info->pool.size)
			return -EREMCHG;

		r = bus1_peer_names_check(peer, param->names, param->size - sizeof(*param));
		if (r < 0)
			return r;

		return -EISCONN;
	}

	/*
	 * The domain-reference and peer-lock guarantee that no other
	 * connect, disconnect, or teardown can race us (they wait for us). We
	 * also verified that the peer is NEW. Hence, peer->info must be
	 * NULL. We still verify it, just to be safe.
	 */
	if (WARN_ON(rcu_dereference_protected(peer->info,
					lockdep_is_held(&domain->active) &&
					lockdep_is_held(&peer->rwlock))))
		return -EISCONN;

	/* allocate new peer_info object */
	peer_info = bus1_peer_info_new(param);
	if (IS_ERR(peer_info))
		return PTR_ERR(peer_info);

	/* pin a user object */
	peer_info->user = bus1_user_acquire(domain, uid);
	if (IS_ERR(peer_info->user)) {
		r = PTR_ERR(peer_info->user);
		peer_info->user = NULL;
		goto error;
	}

	/* allocate names */
	name = param->names;
	remaining = param->size - sizeof(*param);
	while (remaining > 0) {
		n = strnlen(name, remaining);
		if (n == 0 || n == remaining) {
			r = -EMSGSIZE;
			goto error;
		}

		peer_name = bus1_peer_name_new(name, peer);
		if (IS_ERR(peer_name)) {
			r = PTR_ERR(peer_name);
			goto error;
		}

		/* insert into names list */
		peer_name->next = names;
		names = peer_name;

		name += n + 1;
		remaining -= n + 1;
	}

	mutex_lock(&domain->lock);
	write_seqcount_begin(&domain->seqcount);

	/* link into names rbtree */
	for (peer_name = names; peer_name; peer_name = peer_name->next) {
		r = bus1_peer_name_add(peer_name, domain);
		if (r < 0)
			goto error_unlock;
	}

	/* link into rbtree, we know it must be at the tail */
	last = rb_last(&domain->map_peers);
	if (last)
		rb_link_node_rcu(&peer->rb, last, &last->rb_right);
	else
		rb_link_node_rcu(&peer->rb, NULL, &domain->map_peers.rb_node);
	rb_insert_color(&peer->rb, &domain->map_peers);

	/* acquire ID and activate peer */
	peer->id = ++domain->info->peer_ids;
	peer->names = names;
	rcu_assign_pointer(peer->info, peer_info);
	++domain->n_peers;
	bus1_active_activate(&peer->active);

	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);

	/* provide ID for caller, pool-size is already set */
	param->unique_id = peer->id;

	return 0;

error_unlock:
	for (peer_name = names; peer_name; peer_name = peer_name->next)
		bus1_peer_name_remove(peer_name, domain);
	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);
error:
	while ((peer_name = names)) {
		names = names->next;
		bus1_peer_name_free(peer_name);
	}
	peer_info->user = bus1_user_release(peer_info->user);
	bus1_peer_info_free(peer_info);
	return r;
}

static int bus1_peer_connect_reset(struct bus1_peer *peer,
				   struct bus1_domain *domain,
				   struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;
	struct rb_node *last;

	/*
	 * If a RESET is requested, we atomically DISCONNECT and
	 * CONNECT the peer. Luckily, all we have to do is allocate a
	 * new ID and re-add it to the rb-tree. Then we tell the peer
	 * itself to flush any pending data. There might be operations
	 * in-flight, that finish after we reset the peer. All those
	 * operations must be tagged with the old id, though (see
	 * bus1_peer_dereference() for details). Therefore, those
	 * operations can be silently ignored and will be gc'ed later
	 * on if their tag is outdated.
	 */

	lockdep_assert_held(&domain->active);
	lockdep_assert_held(&peer->rwlock);

	/* cannot reset a peer that was never connected */
	if (bus1_active_is_new(&peer->active))
		return -ENOTCONN;

	/* verify pool-size is unset and no names are appended */
	if (param->pool_size != 0 || param->size > sizeof(*param))
		return -EINVAL;

	/*
	 * We hold domain reference and peer-lock, hence domain/peer teardown
	 * must wait for us. Our caller already verified we haven't been torn
	 * down, yet. We verified that the peer is not NEW. Hence, the peer
	 * pointer must be valid.
	 * Be safe and verify it anyway.
	 */
	peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&domain->active) &&
					lockdep_is_held(&peer->rwlock));
	if (WARN_ON(!peer_info))
		return -ESHUTDOWN;

	mutex_lock(&domain->lock);
	write_seqcount_begin(&domain->seqcount);

	/* remove from rb-tree, and change the ID */
	rb_erase(&peer->rb, &domain->map_peers);
	peer->id = ++domain->info->peer_ids;

	/* insert at the tail again */
	last = rb_last(&domain->map_peers);
	if (last)
		rb_link_node_rcu(&peer->rb, last, &last->rb_right);
	else
		rb_link_node_rcu(&peer->rb, NULL,
				 &domain->map_peers.rb_node);
	rb_insert_color(&peer->rb, &domain->map_peers);

	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);

	/* provide information for caller */
	param->unique_id = peer->id;
	param->pool_size = peer_info->pool.size;

	/* safe to call outside of domain-lock; we still hold the peer-lock */
	bus1_peer_info_reset(peer_info, peer->id);

	return 0;
}

static int bus1_peer_connect_query(struct bus1_peer *peer,
				   struct bus1_domain *domain,
				   struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&domain->active);
	lockdep_assert_held(&peer->rwlock);

	/* cannot query a peer that was never connected */
	if (bus1_active_is_new(&peer->active))
		return -ENOTCONN;

	/*
	 * We hold a domain-reference and peer-lock, the caller already
	 * verified we're not disconnected. Barriers guarantee that the peer is
	 * accessible, and both the domain teardown and peer-disconnect have to
	 * wait for us to finish. However, to be safe, check for NULL anyway.
	 */
	peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&domain->active) &&
					lockdep_is_held(&peer->rwlock));
	if (WARN_ON(!peer_info))
		return -ESHUTDOWN;

	param->unique_id = peer->id;
	param->pool_size = peer_info->pool.size;

	return 0;
}

static int bus1_peer_ioctl_connect(struct bus1_peer *peer,
				   struct bus1_domain *domain,
				   const struct file *file,
				   unsigned long arg)
{
	struct bus1_cmd_connect __user *uparam = (void __user *)arg;
	struct bus1_cmd_connect *param;
	int r;

	/*
	 * The domain-active-reference guarantees that a domain teardown waits
	 * for us, before it starts the force-disconnect on all clients.
	 */
	lockdep_assert_held(&domain->active);

	param = bus1_import_dynamic_ioctl(arg, sizeof(*param));
	if (IS_ERR(param))
		return PTR_ERR(param);

	/* check for validity of all flags */
	if (param->flags & ~(BUS1_CONNECT_FLAG_PEER |
			     BUS1_CONNECT_FLAG_MONITOR |
			     BUS1_CONNECT_FLAG_QUERY |
			     BUS1_CONNECT_FLAG_RESET))
		return -EINVAL;
	/* only one mode can be specified */
	if (!!(param->flags & BUS1_CONNECT_FLAG_PEER) +
	    !!(param->flags & BUS1_CONNECT_FLAG_MONITOR) +
	    !!(param->flags & BUS1_CONNECT_FLAG_RESET) > 1)
		return -EINVAL;
	/* unique-id is never used as input */
	if (param->unique_id != 0)
		return -EINVAL;
	/* only root can claim names */
	if (!file_ns_capable(file, domain->info->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	if (bus1_active_is_deactivated(&peer->active)) {
		/* all fails, if the peer was already disconnected */
		r = -ESHUTDOWN;
	} else if (param->flags & (BUS1_CONNECT_FLAG_PEER |
				   BUS1_CONNECT_FLAG_MONITOR)) {
		/* fresh connect of a new peer */
		r = bus1_peer_connect_new(peer, domain, file->f_cred->uid,
					  param);
	} else if (param->flags & BUS1_CONNECT_FLAG_RESET) {
		/* reset of the peer requested */
		r = bus1_peer_connect_reset(peer, domain, param);
	} else if (param->flags & BUS1_CONNECT_FLAG_QUERY) {
		/* fallback: no special operation specified, just query */
		r = bus1_peer_connect_query(peer, domain, param);
	} else {
		r = -EINVAL; /* no mode specified */
	}

	up_write(&peer->rwlock);

	/*
	 * QUERY can be combined with any CONNECT operation. On success, it
	 * causes the peer-id and pool-size to be copied back to user-space.
	 * All handlers above must provide that information in @param for this
	 * to copy it back.
	 */
	if (r >= 0 && (param->flags & BUS1_CONNECT_FLAG_QUERY)) {
		if (put_user(param->unique_id, &uparam->unique_id) ||
		    put_user(param->pool_size, &uparam->pool_size))
			r = -EFAULT; /* Don't care.. keep what we did so far */
	}

	kfree(param);
	return r;
}

static int bus1_peer_ioctl_resolve(struct bus1_peer *peer,
				   struct bus1_domain *domain,
				   unsigned long arg)
{
	struct bus1_cmd_resolve __user *uparam = (void __user *)arg;
	struct bus1_cmd_resolve *param;
	struct bus1_peer_name *peer_name;
	struct rb_node *n;
	size_t namelen;
	unsigned seq;
	int r, v;

	lockdep_assert_held(&domain->active);

	param = bus1_import_dynamic_ioctl(arg, sizeof(*param));
	if (IS_ERR(param))
		return PTR_ERR(param);

	/* no flags are known at this time */
	if (param->flags) {
		r = -EINVAL;
		goto exit;
	}

	/* result must be cleared by caller */
	if (param->unique_id != 0) {
		r = -EINVAL;
		goto exit;
	}

	/* reject overlong/short names early */
	namelen = param->size - sizeof(*param);
	if (namelen < 2 || namelen > BUS1_NAME_MAX_SIZE) {
		r = -ENXIO;
		goto exit;
	}

	/* name must be zero-terminated */
	if (param->name[namelen - 1] != 0) {
		r = -EINVAL;
		goto exit;
	}

	/* find unique-id of named peer */
	seq = raw_seqcount_begin(&domain->seqcount);
	do {
		rcu_read_lock();
		n = rcu_dereference(domain->map_names.rb_node);
		while (n) {
			peer_name = container_of(n, struct bus1_peer_name, rb);
			v = strcmp(param->name, peer_name->name);
			if (v == 0) {
				if (bus1_active_is_active(&peer_name->peer->active))
					param->unique_id = peer_name->peer->id;
				break;
			} else if (v < 0) {
				n = rcu_dereference(n->rb_left);
			} else /* if (v > 0) */ {
				n = rcu_dereference(n->rb_right);
			}
		}
		rcu_read_unlock();
	} while (!n &&
		 read_seqcount_retry(&domain->seqcount, seq) &&
		 ((seq = read_seqcount_begin(&domain->seqcount)), true));

	if (!n)
		r = -ENXIO; /* not found, or deactivated */
	else if (put_user(param->unique_id, &uparam->unique_id))
		r = -EFAULT;
	else
		r = 0;

exit:
	kfree(param);
	return r;
}

static int bus1_peer_ioctl_slice_release(struct bus1_peer *peer,
					 unsigned long arg)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	u64 offset;
	int r;

	r = bus1_import_fixed_ioctl(&offset, arg, sizeof(offset));
	if (r < 0)
		return r;

	mutex_lock(&peer_info->lock);
	r = bus1_pool_release_user(&peer_info->pool, offset);
	mutex_unlock(&peer_info->lock);

	return r;
}

static int bus1_peer_ioctl_track(struct bus1_peer *tracker,
				 struct bus1_domain *domain,
				 unsigned long arg)
{
	struct bus1_peer_info *tracker_info, *trackee_info;
	struct bus1_peer_track *track = NULL, *iter;
	struct rb_node *prev, **slot;
	struct bus1_peer *trackee;
	u64 id;
	int r;

	lockdep_assert_held(&tracker->active);

	r = bus1_import_fixed_ioctl(&id, arg, sizeof(id));
	if (r < 0)
		return r;

	/* pin remote */
	trackee = bus1_peer_acquire_raw_by_id(domain, id);
	if (!trackee)
		return -ENXIO;

	/* prevent tracking yourself */
	if (trackee == tracker) {
		r = -ELOOP;
		goto exit;
	}

	track = kmalloc(sizeof(*track), GFP_KERNEL);
	if (!track) {
		r = -ENOMEM;
		goto exit;
	}

	track->tracker = tracker;
	track->trackee = trackee;

	/* lock both peers (order is defined by absolute address) */
	tracker_info = bus1_peer_dereference(tracker);
	trackee_info = bus1_peer_dereference(trackee);
	if (tracker_info < trackee_info) {
		mutex_lock(&tracker_info->lock);
		mutex_lock_nested(&trackee_info->lock, 1);
	} else {
		mutex_lock(&trackee_info->lock);
		mutex_lock_nested(&tracker_info->lock, 1);
	}

	/* insert into tracker, prevent duplicates */
	slot = &tracker_info->map_trackees.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = container_of(prev, struct bus1_peer_track, rb_tracker);
		if (trackee == iter->trackee) {
			r = -EALREADY;
			goto exit_unlock;
		} else if (trackee < iter->trackee) {
			slot = &prev->rb_left;
		} else /* if (trackee > iter->trackee) */ {
			slot = &prev->rb_right;
		}
	}
	rb_link_node(&track->rb_tracker, prev, slot);
	rb_insert_color(&track->rb_tracker, &tracker_info->map_trackees);

	/* link into trackee */
	list_add_tail(&track->link_trackee, &trackee_info->list_trackers);

	/* two ref-counts, one for each link */
	kref_init(&track->ref);
	kref_get(&track->ref);

	track = NULL;
	r = 0;

exit_unlock:
	mutex_unlock(&trackee_info->lock);
	mutex_unlock(&tracker_info->lock);
exit:
	bus1_peer_release_raw(trackee);
	kfree(track);
	return r;
}

static int bus1_peer_ioctl_untrack(struct bus1_peer *tracker,
				   struct bus1_domain *domain,
				   unsigned long arg)
{
	struct bus1_peer_info *tracker_info = bus1_peer_dereference(tracker);
	struct bus1_peer_info *trackee_info;
	struct bus1_peer_track *track;
	struct bus1_peer *trackee;
	struct rb_node *n;
	u64 id;
	int r;

	lockdep_assert_held(&tracker->active);

	r = bus1_import_fixed_ioctl(&id, arg, sizeof(id));
	if (r < 0)
		return r;

	/*
	 * Intuitively, one would simply iterate map_trackees until we find an
	 * entry for @id. However, this tree is *not* indexed by the peer id,
	 * hence, we have to do the double lookup here.
	 */
	trackee = bus1_peer_acquire_raw_by_id(domain, id);
	if (!trackee)
		return -ENXIO;

	/* search for track entry and unlink it locally, if found */
	mutex_lock(&tracker_info->lock);
	n = tracker_info->map_trackees.rb_node;
	while (n) {
		track = container_of(n, struct bus1_peer_track, rb_tracker);
		if (trackee < track->trackee) {
			n = n->rb_left;
		} else if (trackee > track->trackee) {
			n = n->rb_right;
		} else {
			rcu_assign_pointer(track->tracker, NULL);
			rb_erase(&track->rb_tracker,
				 &tracker_info->map_trackees);
			/* keep the reference, so @track stays valid */
			break;
		}
	}
	mutex_unlock(&tracker_info->lock);

	if (!n) {
		r = -ENXIO;
		goto exit;
	}

	/* now unlink @track from the remote peer */
	trackee_info = bus1_peer_dereference(trackee);
	mutex_lock(&trackee_info->lock);
	if (rcu_access_pointer(track->trackee)) {
		rcu_assign_pointer(track->trackee, NULL);
		list_del(&track->link_trackee);
		kref_put(&track->ref, bus1_peer_track_no_free);
	}
	mutex_unlock(&trackee_info->lock);

	/* at last we drop the local reference used to pin the object */
	kref_put(&track->ref, bus1_peer_track_free);
	r = 0;

exit:
	bus1_peer_release_raw(trackee);
	return r;
}

static int bus1_peer_ioctl_send(struct bus1_peer *peer,
				struct bus1_domain *domain,
				unsigned long arg)
{
	struct bus1_transaction *transaction = NULL;
	/* Use a stack-allocated buffer for the transaction object if it fits */
	u8 buf[512];
	const u64 __user *ptr_dest;
	struct bus1_cmd_send param;
	u64 destination;
	size_t i;
	int r;

	r = bus1_import_fixed_ioctl(&param, arg, sizeof(param));
	if (r < 0)
		return r;

	if (unlikely(param.flags & ~(BUS1_SEND_FLAG_IGNORE_UNKNOWN |
				     BUS1_SEND_FLAG_CONVEY_ERRORS)))
		return -EINVAL;

	/* check basic limits; avoids integer-overflows later on */
	if (unlikely(param.n_vecs > BUS1_VEC_MAX) ||
	    unlikely(param.n_fds > BUS1_FD_MAX))
		return -EMSGSIZE;

	/* 32bit pointer validity checks */
	if (unlikely(param.ptr_destinations !=
		     (u64)(unsigned long)param.ptr_destinations) ||
	    unlikely(param.ptr_vecs !=
		     (u64)(unsigned long)param.ptr_vecs) ||
	    unlikely(param.ptr_fds !=
		     (u64)(unsigned long)param.ptr_fds))
		return -EFAULT;

	/* peer is pinned, hence domain_info and ID can be accessed freely */
	transaction = bus1_transaction_new_from_user(domain, domain->info,
						     peer->id, &param, buf,
						     sizeof(buf),
						     bus1_in_compat_syscall());
	if (IS_ERR(transaction))
		return PTR_ERR(transaction);

	ptr_dest = (const u64 __user *)(unsigned long)param.ptr_destinations;
	if (param.n_destinations == 1) { /* Fastpath: unicast */
		if (get_user(destination, ptr_dest)) {
			r = -EFAULT; /* faults are always fatal */
			goto exit;
		}

		r = bus1_transaction_commit_for_id(transaction, destination,
						   param.flags);
		if (r < 0)
			goto exit;
	} else { /* Slowpath: any message */
		for (i = 0; i < param.n_destinations; ++i) {
			if (get_user(destination, ptr_dest + i)) {
				r = -EFAULT; /* faults are always fatal */
				goto exit;
			}

			r = bus1_transaction_instantiate_for_id(transaction,
								destination,
								param.flags);
			if (r < 0)
				goto exit;
		}

		bus1_transaction_commit(transaction);
	}

	r = 0;

exit:
	bus1_transaction_free(transaction, transaction != (void*)buf);
	return r;
}

static int bus1_peer_ioctl_recv(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_cmd_recv __user *uparam = (void __user *)arg;
	struct bus1_queue_entry *entry;
	struct bus1_cmd_recv param;
	size_t wanted_fds, n_fds = 0;
	int r, *t, *fds = NULL;
	struct kvec vec;

	r = bus1_import_fixed_ioctl(&param, arg, sizeof(param));
	if (r < 0)
		return r;

	if (unlikely(param.flags & ~(BUS1_RECV_FLAG_PEEK)))
		return -EINVAL;

	if (unlikely(param.msg_offset != BUS1_OFFSET_INVALID) ||
	    unlikely(param.msg_size != 0) ||
	    unlikely(param.msg_fds != 0))
		return -EINVAL;

	/*
	 * Peek at the first message to fetch the FD count. We need to
	 * pre-allocate FDs, to avoid dropping messages due to FD exhaustion.
	 * If no entry is queued, we can bail out early.
	 * Note that this is just a fast-path optimization. Anyone might race
	 * us for message retrieval, so we have to check it again below.
	 */
	rcu_read_lock();
	entry = bus1_queue_peek_rcu(&peer_info->queue);
	wanted_fds = entry ? entry->n_files : 0;
	rcu_read_unlock();
	if (!entry)
		return -EAGAIN;

	/*
	 * Deal with PEEK first. This is simple. Just look at the first queued
	 * message, publish the slice and return the information to user-space.
	 * Keep the entry queued, so it can be peeked multiple times, and
	 * received later on.
	 * We do not install any FDs for PEEK, but provide the number in
	 * msg_fds, anyway.
	 */
	if (param.flags & BUS1_RECV_FLAG_PEEK) {
		mutex_lock(&peer_info->lock);
		entry = bus1_queue_peek(&peer_info->queue);
		if (entry) {
			bus1_pool_publish(&peer_info->pool, entry->slice,
					  &param.msg_offset, &param.msg_size);
			param.msg_fds = entry->n_files;
		}
		mutex_unlock(&peer_info->lock);

		if (!entry)
			return -EAGAIN;

		r = 0;
		goto exit;
	}

	/*
	 * So there is a message queued with 'wanted_fds' attached FDs.
	 * Allocate a temporary buffer to store them, then dequeue the message.
	 * In case someone raced us and the message changed, re-allocate the
	 * temporary buffer and retry.
	 */

	do {
		if (wanted_fds > n_fds) {
			t = krealloc(fds, wanted_fds * sizeof(*fds),
				     GFP_TEMPORARY);
			if (!t) {
				r = -ENOMEM;
				goto exit;
			}

			fds = t;
			for ( ; n_fds < wanted_fds; ++n_fds) {
				r = get_unused_fd_flags(O_CLOEXEC);
				if (r < 0)
					goto exit;

				fds[n_fds] = r;
			}
		}

		mutex_lock(&peer_info->lock);
		entry = bus1_queue_peek(&peer_info->queue);
		if (!entry) {
			/* nothing to do, caught below */
		} else if (entry->n_files > n_fds) {
			/* re-allocate FD array and retry */
			wanted_fds = entry->n_files;
		} else {
			bus1_queue_unlink(&peer_info->queue, entry);
			bus1_pool_publish(&peer_info->pool, entry->slice,
					  &param.msg_offset, &param.msg_size);
			param.msg_fds = entry->n_files;

			/*
			 * Fastpath: If no FD is transmitted, we can avoid the
			 *           second lock below. Directly release the
			 *           slice.
			 */
			if (entry->n_files == 0)
				bus1_pool_release_kernel(&peer_info->pool,
							 entry->slice);
		}
		mutex_unlock(&peer_info->lock);
	} while (wanted_fds > n_fds);

	if (!entry) {
		r = -EAGAIN;
		goto exit;
	}

	while (n_fds > entry->n_files)
		put_unused_fd(fds[--n_fds]);

	if (n_fds > 0) {
		/*
		 * We dequeued the message, we already fetched enough FDs, all
		 * we have to do is copy the FD numbers into the slice and link
		 * the FDs.
		 * The only reason this can fail, is if writing the pool fails,
		 * which itself can only happen during OOM. In that case, we
		 * don't support reverting the operation, but you rather lose
		 * the message. We cannot put it back on the queue (would break
		 * ordering), and we don't want to perform the copy-operation
		 * while holding the queue-lock.
		 * We treat this OOM as if the actual message transaction OOMed
		 * and simply drop the message.
		 */

		vec.iov_base = fds;
		vec.iov_len = n_fds * sizeof(*fds);

		r = bus1_pool_write_kvec(&peer_info->pool, entry->slice,
					 entry->slice->size - vec.iov_len,
					 &vec, 1, vec.iov_len);

		mutex_lock(&peer_info->lock);
		bus1_pool_release_kernel(&peer_info->pool, entry->slice);
		mutex_unlock(&peer_info->lock);

		/* on success, install FDs; on error, see fput() in `exit:' */
		if (r >= 0) {
			for ( ; n_fds > 0; --n_fds)
				fd_install(fds[n_fds - 1],
					   get_file(entry->files[n_fds - 1]));
		} else {
			/* XXX: convey error, just like in transactions */
		}
	} else {
		/* slice is already released, nothing to do */
		r = 0;
	}

	entry->slice = NULL;
	bus1_queue_entry_free(entry);

exit:
	if (r >= 0) {
		if (put_user(param.msg_offset, &uparam->msg_offset) ||
		    put_user(param.msg_size, &uparam->msg_size) ||
		    put_user(param.msg_fds, &uparam->msg_fds))
			r = -EFAULT; /* Don't care.. keep what we did so far */
	}
	while (n_fds > 0)
		put_unused_fd(fds[--n_fds]);
	kfree(fds);
	return r;
}

/**
 * bus1_peer_ioctl() - handle peer ioctl
 * @peer:		peer to work on
 * @domain:		parent domain
 * @file:		file this ioctl is called on
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on the passed peer. @domain must be
 * the parent domain of @peer. The caller must not hold an active reference to
 * either.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl(struct bus1_peer *peer,
		    struct bus1_domain *domain,
		    const struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	int r = -ENOTTY;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
	case BUS1_CMD_RESOLVE:
		/* lock against domain shutdown */
		if (!bus1_domain_acquire(domain))
			return -ESHUTDOWN;

		if (cmd == BUS1_CMD_CONNECT)
			r = bus1_peer_ioctl_connect(peer, domain, file, arg);
		else if (cmd == BUS1_CMD_RESOLVE)
			r = bus1_peer_ioctl_resolve(peer, domain, arg);

		bus1_domain_release(domain);
		break;

	case BUS1_CMD_DISCONNECT:
		/* no arguments allowed, it behaves like the last close() */
		if (arg != 0)
			return -EINVAL;

		return bus1_peer_teardown(peer, domain);

	case BUS1_CMD_SLICE_RELEASE:
	case BUS1_CMD_TRACK:
	case BUS1_CMD_UNTRACK:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		down_read(&peer->rwlock);
		if (!bus1_peer_acquire(peer)) {
			r = -ESHUTDOWN;
		} else {
			if (cmd == BUS1_CMD_SLICE_RELEASE)
				r = bus1_peer_ioctl_slice_release(peer, arg);
			else if (cmd == BUS1_CMD_TRACK)
				r = bus1_peer_ioctl_track(peer, domain, arg);
			else if (cmd == BUS1_CMD_UNTRACK)
				r = bus1_peer_ioctl_untrack(peer, domain, arg);
			else if (cmd == BUS1_CMD_SEND)
				r = bus1_peer_ioctl_send(peer, domain, arg);
			else if (cmd == BUS1_CMD_RECV)
				r = bus1_peer_ioctl_recv(peer, arg);
			bus1_peer_release(peer);
		}
		up_read(&peer->rwlock);
		break;
	}

	return r;
}
