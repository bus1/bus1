/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "active.h"

/*
 * Bias values track states of "active references". They're all negative. If an
 * object is active, its active-ref-counter is >=0 and tracks all active
 * references. Once an object is deactivated, we subtract ACTIVE_BIAS. This
 * means, the counter is now negative but still counts the active references.
 * Once it drops to exactly ACTIVE_BIAS, we know all active references were
 * dropped. Exactly one thread will change it to ACTIVE_RELEASE now, perform
 * cleanup and then put it into ACTIVE_DONE. Once released, all other threads
 * that tried deactivating the node will now be woken up (thus, they wait until
 * the object is fully done).
 * The initial state during object setup is ACTIVE_NEW. If an object is
 * directly deactivated without having ever been active, it is put into
 * ACTIVE_RELEASE_DIRECT instead of ACTIVE_BIAS. This tracks this one-bit state
 * across deactivation. The task putting it into ACTIVE_RELEASE now knows
 * whether the object was active before or not.
 *
 * We support lockdep annotations for 'active references'. We treat active
 * references as a read-trylock, and deactivation as a write-lock.
 *
 * Some archs implement atomic_sub(v) with atomic_add(-v), so reserve INT_MIN
 * to avoid overflows if multiplied by -1.
 */
#define BUS1_ACTIVE_RELEASE_DIRECT	(BUS1_ACTIVE_BIAS - 1)
#define BUS1_ACTIVE_RELEASE		(BUS1_ACTIVE_BIAS - 2)
#define BUS1_ACTIVE_DONE		(BUS1_ACTIVE_BIAS - 3)
#define BUS1_ACTIVE_NEW			(BUS1_ACTIVE_BIAS - 4)
#define _BUS1_ACTIVE_RESERVED		(BUS1_ACTIVE_BIAS - 5)

/**
 * bus1_active_init_private() - initialize object
 * @active:	object to initialize
 *
 * This initializes an active-object. The initial state is NEW, and as such no
 * active reference can be acquired. The object must be activated first.
 *
 * This is an internal helper. Always use the public bus1_active_init() macro
 * which does proper lockdep initialization for private key classes.
 */
void bus1_active_init_private(struct bus1_active *active)
{
	atomic_set(&active->count, BUS1_ACTIVE_NEW);
}

/**
 * bus1_active_deinit() - destroy object
 * @active:	object to destroy
 *
 * Destroy an active-object. The object must have been initialized via
 * bus1_active_init(), deactivated via bus1_active_deactivate(), drained via
 * bus1_active_drain() and cleaned via bus1_active_cleanup(), before you can
 * destroy it. Alternatively, it can also be destroyed if still in state NEW.
 *
 * This function only does sanity checks, it does not modify the object itself.
 * There is no allocated memory, so there is nothing to do.
 */
void bus1_active_deinit(struct bus1_active *active)
{
	int v;

	v = atomic_read(&active->count);
	WARN_ON(v != BUS1_ACTIVE_NEW && v != BUS1_ACTIVE_DONE);
}

/**
 * bus1_active_is_new() - check whether object is new
 * @active:	object to check
 *
 * This checks whether the object is new, that is, it was never activated nor
 * deactivated.
 *
 * Return: True if new, false if not.
 */
bool bus1_active_is_new(struct bus1_active *active)
{
	return atomic_read(&active->count) == BUS1_ACTIVE_NEW;
}

/**
 * bus1_active_is_active() - check whether object is active
 * @active:	object to check
 *
 * This checks whether the given active-object is active. That is, the object
 * was already activated, but not deactivated, yet.
 *
 * Note that this function does not give any guarantee that the object is still
 * active/inactive at the time this call returns. It only serves as a barrier.
 *
 * Return: True if active, false if not.
 */
bool bus1_active_is_active(struct bus1_active *active)
{
	return atomic_read(&active->count) >= 0;
}

/**
 * bus1_active_is_deactivated() - check whether object was deactivated
 * @active:	object to check
 *
 * This checks whether the given active-object was already deactivated. That
 * is, the object was actively deactivated (state NEW does *not* count as
 * deactivated) via bus1_active_deactivate().
 *
 * Once this function returns true, it cannot change again on this object.
 *
 * Return: True if already deactivated, false if not.
 */
bool bus1_active_is_deactivated(struct bus1_active *active)
{
	int v = atomic_read(&active->count);

	return v > BUS1_ACTIVE_NEW && v < 0;
}

/**
 * bus1_active_is_drained() - check whether object is drained
 * @active:	object to check
 *
 * This checks whether the given object was already deactivated and is fully
 * drained. That is, no active references to the object exist, nor can they be
 * acquired, anymore.
 *
 * Return: True if drained, false if not.
 */
bool bus1_active_is_drained(struct bus1_active *active)
{
	int v = atomic_read(&active->count);

	return v > BUS1_ACTIVE_NEW && v <= BUS1_ACTIVE_BIAS;
}

/**
 * bus1_active_activate() - activate object
 * @active:	object to activate
 *
 * This activates the given object, if it is still in state NEW. Otherwise, it
 * is a no-op (and the object might already be deactivated).
 *
 * Once this returns successfully, active references can be acquired.
 *
 * Return: True if this call activated it, false if it was already activated,
 *         or deactivated.
 */
bool bus1_active_activate(struct bus1_active *active)
{
	return atomic_cmpxchg(&active->count,
			      BUS1_ACTIVE_NEW, 0) == BUS1_ACTIVE_NEW;
}

/**
 * bus1_active_deactivate() - deactivate object
 * @active:	object to deactivate
 *
 * This deactivates the given object, if not already done by someone else. Once
 * this returns, no new active references can be acquired.
 *
 * Return: True if this call deactivated the object, false if it was already
 *         deactivated by someone else.
 */
bool bus1_active_deactivate(struct bus1_active *active)
{
	int v, v1;

	v = atomic_cmpxchg(&active->count,
			   BUS1_ACTIVE_NEW, BUS1_ACTIVE_RELEASE_DIRECT);
	if (unlikely(v == BUS1_ACTIVE_NEW))
		return true;

	/*
	 * This adds BUS1_ACTIVE_BIAS to the counter, unless its negative:
	 *     atomic_add_unless_negative(&active->count, BUS1_ACTIVE_BIAS)
	 * No such global helper exists, so it is inline here.
	 */
	for (v = atomic_read(&active->count); v >= 0; v = v1) {
		v1 = atomic_cmpxchg(&active->count, v, v + BUS1_ACTIVE_BIAS);
		if (likely(v1 == v))
			return true;
	}

	return false;
}

/**
 * bus1_active_drain() - drain active references
 * @active:	object to drain
 * @waitq:	wait-queue linked to @active
 *
 * This waits for all active-references on @active to be dropped. It uses the
 * passed wait-queue to sleep. It must be the same wait-queue that is used when
 * calling bus1_active_release().
 *
 * The caller must guarantee that bus1_active_deactivate() was called before.
 *
 * This function can be safely called in parallel on multiple CPUs.
 *
 * Semantically (and also enforced by lockdep), this call behaves like a
 * down_write(), followed by an up_write(), on this active object.
 */
void bus1_active_drain(struct bus1_active *active, wait_queue_head_t *waitq)
{
	if (WARN_ON(!bus1_active_is_deactivated(active)))
		return;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * We pretend this is a down_write_interruptible() and all but
	 * the release-context get interrupted. This is required, as we
	 * cannot call lock_acquired() on multiple threads without
	 * synchronization. Hence, only the release-context will do
	 * this, all others just release the lock.
	 */
	lock_acquire_exclusive(&active->dep_map,	/* lock */
			       0,			/* subclass */
			       0,			/* try-lock */
			       NULL,			/* nest underneath */
			       _RET_IP_);		/* IP */
	if (atomic_read(&active->count) > BUS1_ACTIVE_BIAS)
		lock_contended(&active->dep_map, _RET_IP_);
#endif

	/* wait until all active references were dropped */
	wait_event(*waitq, atomic_read(&active->count) <= BUS1_ACTIVE_BIAS);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Pretend that no-one got the lock, but everyone got interrupted
	 * instead. That is, they released the lock without ever actually
	 * getting it locked.
	 */
	lock_release(&active->dep_map,		/* lock */
		     1,				/* nested (no-op) */
		     _RET_IP_);			/* instruction pointer */
#endif
}

/**
 * bus1_active_cleanup() - cleanup drained object
 * @active:	object to release
 * @waitq:	wait-queue linked to @active, or NULL
 * @cleanup:	cleanup callback, or NULL
 * @userdata:	userdata for callback
 *
 * This performs the final object cleanup. The caller must guarantee that the
 * object is drained, by calling bus1_active_drain().
 *
 * This function invokes the passed cleanup callback on the object. However, it
 * guarantees that this is done exactly once. If there're multiple parallel
 * callers, this will pick one randomly and make all others wait until it is
 * done. If you call this after it was already cleaned up, this is a no-op
 * and only serves as barrier.
 *
 * If @waitq is NULL, the wait is skipped and the call returns immediately. In
 * this case, another thread has entered before, but there is no guarantee that
 * they finished executing the cleanup callback, yet.
 *
 * If @waitq is non-NULL, this call behaves like a down_write(), followed by an
 * up_write(), just like bus1_active_drain(). If @waitq is NULL, this rather
 * behaves like a down_write_trylock(), optionally followed by an up_write().
 *
 * Return: True if this is the thread that released it, false otherwise.
 */
bool bus1_active_cleanup(struct bus1_active *active,
			 wait_queue_head_t *waitq,
			 void (*cleanup)(struct bus1_active *, void *),
			 void *userdata)
{
	int v;

	if (WARN_ON(!bus1_active_is_drained(active)))
		return false;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * We pretend this is a down_write_interruptible() and all but
	 * the release-context get interrupted. This is required, as we
	 * cannot call lock_acquired() on multiple threads without
	 * synchronization. Hence, only the release-context will do
	 * this, all others just release the lock.
	 */
	lock_acquire_exclusive(&active->dep_map,/* lock */
			       0,		/* subclass */
			       !waitq,		/* try-lock */
			       NULL,		/* nest underneath */
			       _RET_IP_);	/* IP */
#endif

	/* mark object as RELEASE */
	v = atomic_cmpxchg(&active->count,
			   BUS1_ACTIVE_RELEASE_DIRECT, BUS1_ACTIVE_RELEASE);
	if (v != BUS1_ACTIVE_RELEASE_DIRECT)
		v = atomic_cmpxchg(&active->count,
				   BUS1_ACTIVE_BIAS, BUS1_ACTIVE_RELEASE);

	/*
	 * If this is the thread that marked the object as RELEASE, we
	 * perform the actual release. Otherwise, we wait until the
	 * release is done and the node is marked as DRAINED.
	 */
	if (v == BUS1_ACTIVE_BIAS || v == BUS1_ACTIVE_RELEASE_DIRECT) {

#ifdef CONFIG_DEBUG_LOCK_ALLOC
		/* we're the release-context and acquired the lock */
		lock_acquired(&active->dep_map, _RET_IP_);
#endif

		if (cleanup)
			cleanup(active, userdata);

		/* mark as DONE */
		atomic_set(&active->count, BUS1_ACTIVE_DONE);
		if (waitq)
			wake_up_all(waitq);
	} else if (waitq) {

#ifdef CONFIG_DEBUG_LOCK_ALLOC
		/* we're contended against the release context */
		lock_contended(&active->dep_map, _RET_IP_);
#endif

		/* wait until object is DONE */
		wait_event(*waitq,
			   atomic_read(&active->count) == BUS1_ACTIVE_DONE);
	}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * No-one but the release-context acquired the lock. However,
	 * that does not matter as we simply treat this as
	 * 'interrupted'. Everyone releases the lock, but only one
	 * caller really got it.
	 */
	lock_release(&active->dep_map,	/* lock */
		     1,			/* nested (no-op) */
		     _RET_IP_);		/* instruction pointer */
#endif

	/* true if we released it */
	return v == BUS1_ACTIVE_BIAS || v == BUS1_ACTIVE_RELEASE_DIRECT;
}

/**
 * bus1_active_lockdep_acquired() - acquire lockdep reader
 * @active:	object to acquire lockdep reader of, or NULL
 *
 * Whenever you acquire an active reference via bus1_active_acquire(), this
 * function is implicitly called afterwards. It enables lockdep annotations and
 * tells lockdep that you acquired the active reference.
 *
 * However, lockdep cannot support arbitrary depths, hence, we allow
 * temporarily dropping the lockdep-annotation via
 * bus1_active_lockdep_release(), and acquiring them later again via
 * bus1_active_lockdep_acquire().
 *
 * Example: If you need to pin a large number of objects, you would acquire each
 *          of them individually via bus1_active_acquire(). Then you would
 *          perform state tracking, etc. on that object. Before you continue
 *          with the next, you call bus1_active_lockdep_released(), to pretend
 *          you released the lock (but you still retain your active reference).
 *          Now you continue with pinning the next object, etc. until you
 *          pinned all objects you need.
 *
 *          If you now need to access one of your pinned objects (or want to
 *          release them eventually), you call bus1_active_lockdep_acquired()
 *          before accessing the object. This enables the lockdep annotations
 *          again. This cannot fail, ever. You still own the active reference
 *          at all times.
 *          Once you're done with the single object, you either release your
 *          entire active reference via bus1_active_release(), or you
 *          temporarily disable lockdep via bus1_active_lockdep_released()
 *          again, in case you need the pinned object again later.
 *
 * Note that you can acquired multiple active references just fine. The only
 * reason those lockdep helpers are provided, is if you need to acquire a
 * *large* number at the same time. Lockdep is usually limited to a depths of 64
 * so you cannot hold more locks at the same time.
 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
void bus1_active_lockdep_acquired(struct bus1_active *active)
{
	if (active)
		lock_acquire_shared(&active->dep_map,	/* lock */
				    0,			/* subclass */
				    1,			/* try-lock */
				    NULL,		/* nest underneath */
				    _RET_IP_);		/* IP */
}
#endif

/**
 * bus1_active_lockdep_released() - release lockdep reader
 * @active:	object to release lockdep reader of, or NULL
 *
 * This is the counterpart of bus1_active_lockdep_acquired(). See its
 * documentation for details.
 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
void bus1_active_lockdep_released(struct bus1_active *active)
{
	if (active)
		lock_release(&active->dep_map,	/* lock */
			     1,			/* nested (no-op) */
			     _RET_IP_);		/* instruction pointer */
}
#endif
