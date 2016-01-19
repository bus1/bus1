/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
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
 * references. Once an object is deactivaed, we subtract ACTIVE_BIAS. This
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
#define BUS1_ACTIVE_BIAS		(INT_MIN + 5)
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
 * bus1_active_destroy() - destroy object
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
void bus1_active_destroy(struct bus1_active *active)
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

/*
 * There is no atomic_add_unless_negative(), nor an
 * atomic_sub_unless_negative(), so we implement it here, similarly to their
 * inc and dec counterparts.
 */
static int bus1_active_add_unless_negative(struct bus1_active *active, int add)
{
	int v, v1;

	for (v = atomic_read(&active->count); v >= 0; v = v1) {
		v1 = atomic_cmpxchg(&active->count, v, v + add);
		if (likely(v1 == v))
			return 1;
	}

	return 0;
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
	int v;

	v = atomic_cmpxchg(&active->count,
			   BUS1_ACTIVE_NEW, BUS1_ACTIVE_RELEASE_DIRECT);
	if (v != BUS1_ACTIVE_NEW)
		v = bus1_active_add_unless_negative(active, BUS1_ACTIVE_BIAS);

	return v;
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
	 * Pretend that no-one got the lock, but everyone got interruped
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
			 void (*cleanup) (struct bus1_active *active,
			                  void *userdata),
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

		/* wait until object is DRAINED */
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
 * bus1_active_acquire() - acquire active reference
 * @active:	object to acquire active reference to, or NULL
 *
 * This acquires an active reference to the passed object. If the object was
 * not activated, yet, or if it was already deactivated, this will fail and
 * return NULL. If a reference was successfully acquired, this will return
 * @active.
 *
 * If NULL is passed, this is a no-op and always returns NULL.
 *
 * This behaves as a down_read_trylock(). Use bus1_active_release() to release
 * the reference again and get the matching up_read().
 *
 * Return: @active if reference was acquired, NULL if not.
 */
struct bus1_active *bus1_active_acquire(struct bus1_active *active)
{
	return bus1_active_acquire_nest_lock(active, NULL);
}

/**
 * bus1_active_acquire_nest_lock() - acquire active reference
 * @active:	object to acquire active reference to, or NULL
 * @nest:	lock to nest under, or NULL
 *
 * See bus1_active_acquire() for documentation.
 *
 * This function extends bus1_active_acquire() with a nest-lock annotation for
 * lockdep. Given that this function is a try-lock operation, its ordering is
 * irrelevant. However, lockdep cannot know this, and usually doesn't have to
 * know this, as long as we only acquire a fixed set of references at the same
 * time. Some code-paths require huge sets of those references, though. Those
 * paths can use this function in combination with a nest-lock to explicitly
 * tell lockdep to ignore acquisition order for this set of locks (we kind of
 * misuse the nest-lock feature, but it should be fine).
 *
 * Return: @active if reference was acquired, NULL if not.
 */
struct bus1_active *bus1_active_acquire_nest_lock(struct bus1_active *active,
						  struct lockdep_map *nest)
{
	bool res;

	res = active && atomic_inc_unless_negative(&active->count);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (res)
		lock_acquire_shared(&active->dep_map,	/* lock */
				    0,			/* subclass */
				    1,			/* try-lock */
				    nest,		/* nest underneath */
				    _RET_IP_);		/* IP */
#endif

	return res ? active : NULL;
}

/**
 * bus1_active_release() - release active reference
 * @active:	object to release active reference of, or NULL
 * @waitq:	wait-queue linked to @active, or NULL
 *
 * This releases an active reference that was previously acquired via
 * bus1_active_acquire().
 *
 * This is a no-op if NULL is passed.
 *
 * This behaves like an up_read().
 *
 * Return: NULL is returned.
 */
struct bus1_active *bus1_active_release(struct bus1_active *active,
					wait_queue_head_t *waitq)
{
	if (active) {
#ifdef CONFIG_DEBUG_LOCK_ALLOC
		lock_release(&active->dep_map,	/* lock */
			     1,			/* nested (no-op) */
			     _RET_IP_);		/* instruction pointer */
#endif
		if (atomic_dec_return(&active->count) == BUS1_ACTIVE_BIAS)
			if (waitq)
				wake_up(waitq);
	}

	return NULL;
}
