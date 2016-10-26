#ifndef __BUS1_ACTIVE_H
#define __BUS1_ACTIVE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Active References
 *
 * The bus1_active object implements active references. They work similarly to
 * plain object reference counters, but allow disabling any new references from
 * being taken.
 *
 * Each bus1_active object goes through a set of states:
 *   NEW:       Initial state, no active references can be acquired
 *   ACTIVE:    Live state, active references can be acquired
 *   DRAINING:  Deactivated but lingering, no active references can be acquired
 *   DRAINED:   Deactivated and all active references were dropped
 *   RELEASED:  Fully drained and synchronously released
 *
 * Initially, all bus1_active objects are in state NEW. As soon as they're
 * activated, they enter ACTIVE and active references can be acquired. This is
 * the normal, live state. Once the object is deactivated, it enters state
 * DRAINING. No new active references can be acquired, but some threads might
 * still own active references. Once all those are dropped, the object enters
 * state DRAINED. Now the object can be released a *single* time, before it
 * enters state RELEASED and is finished. It cannot be re-used anymore.
 *
 * Active-references are very useful to track threads that call methods on an
 * object. As long as a method is running, an active reference is held, and as
 * such the object is usually protected from being destroyed. The destructor of
 * the object needs to deactivate *and* drain the object, before releasing
 * resources.
 *
 * Note that active-references cannot be used to manage their own backing
 * memory. That is, they do not replace normal reference counts.
 */

#include <linux/atomic.h>
#include <linux/lockdep.h>
#include <linux/sched.h>
#include <linux/wait.h>

/* base value for counter-bias, see BUS1_ACTIVE_* constants for details */
#define BUS1_ACTIVE_BIAS		(INT_MIN + 5)

/**
 * struct bus1_active - active references
 * @count:	active reference counter
 * @dep_map:	lockdep annotations
 *
 * This object should be treated like a simple atomic_t. It will only contain
 * more fields in the case of lockdep-enabled compilations.
 *
 * Users must embed this object into their parent structures and create/destroy
 * it via bus1_active_init() and bus1_active_deinit().
 */
struct bus1_active {
	atomic_t count;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
};

void bus1_active_init_private(struct bus1_active *active);
void bus1_active_deinit(struct bus1_active *active);
bool bus1_active_is_new(struct bus1_active *active);
bool bus1_active_is_active(struct bus1_active *active);
bool bus1_active_is_deactivated(struct bus1_active *active);
bool bus1_active_is_drained(struct bus1_active *active);
bool bus1_active_activate(struct bus1_active *active);
bool bus1_active_deactivate(struct bus1_active *active);
void bus1_active_drain(struct bus1_active *active, wait_queue_head_t *waitq);
bool bus1_active_cleanup(struct bus1_active *active,
			 wait_queue_head_t *waitq,
			 void (*cleanup) (struct bus1_active *, void *),
			 void *userdata);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#  define bus1_active_init(_active) 					\
	({								\
		static struct lock_class_key bus1_active_lock_key;	\
		lockdep_init_map(&(_active)->dep_map, "bus1.active",	\
				 &bus1_active_lock_key, 0);		\
		bus1_active_init_private(_active);			\
	})
void bus1_active_lockdep_acquired(struct bus1_active *active);
void bus1_active_lockdep_released(struct bus1_active *active);
#else
#  define bus1_active_init(_active) bus1_active_init_private(_active)
static inline void bus1_active_lockdep_acquired(struct bus1_active *active) {}
static inline void bus1_active_lockdep_released(struct bus1_active *active) {}
#endif

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
static inline struct bus1_active *
bus1_active_acquire(struct bus1_active *active)
{
	if (active && atomic_inc_unless_negative(&active->count))
		bus1_active_lockdep_acquired(active);
	else
		active = NULL;
	return active;
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
static inline struct bus1_active *
bus1_active_release(struct bus1_active *active, wait_queue_head_t *waitq)
{
	if (active) {
		bus1_active_lockdep_released(active);
		if (atomic_dec_return(&active->count) == BUS1_ACTIVE_BIAS)
			if (waitq)
				wake_up(waitq);
	}
	return NULL;
}

#endif /* __BUS1_ACTIVE_H */
