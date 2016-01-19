#ifndef __BUS1_ACTIVE_H
#define __BUS1_ACTIVE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Active References
 *
 * The bus1_active object implements active references. They work similarly to
 * plain object reference counters, but allow to disable any new references
 * from being taken.
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
 * enters state RELEASED and is finished. It cannot be re-used, anymore.
 *
 * Active-references are very useful to track threads that perform callbacks on
 * an object. As long as a callback is running, an active reference is held,
 * and as such the object is usually protected from being destroyed. The
 * destructor of the object needs to deactivate *and* drain the object, before
 * releasing resources.
 *
 * Note that active-references cannot be used to manage their own backing
 * memory. That is, they do not replace normal reference counts.
 */

#include <linux/atomic.h>
#include <linux/lockdep.h>
#include <linux/wait.h>

/**
 * struct bus1_active - active references
 * @count:	active reference counter
 * @dep_map:	lockdep annotations
 *
 * This object should be treated like a simple atomic_t. Only in the case of
 * lockdep-enabled compilations, it will contain more fields.
 *
 * Users must embed this object into their parent structures and create/destroy
 * it via bus1_active_init() and bus1_active_destroy().
 */
struct bus1_active {
	atomic_t count;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
};

void bus1_active_init_private(struct bus1_active *active);
void bus1_active_destroy(struct bus1_active *active);
bool bus1_active_is_new(struct bus1_active *active);
bool bus1_active_is_active(struct bus1_active *active);
bool bus1_active_is_deactivated(struct bus1_active *active);
bool bus1_active_is_drained(struct bus1_active *active);
bool bus1_active_activate(struct bus1_active *active);
bool bus1_active_deactivate(struct bus1_active *active);
void bus1_active_drain(struct bus1_active *active, wait_queue_head_t *waitq);
bool bus1_active_cleanup(struct bus1_active *active,
			 wait_queue_head_t *waitq,
			 void (*cleanup) (struct bus1_active *active,
		                         void *userdata),
			 void *userdata);
struct bus1_active *bus1_active_acquire(struct bus1_active *active);
struct bus1_active *bus1_active_acquire_nest_lock(struct bus1_active *active,
						  struct lockdep_map *nest);
struct bus1_active *bus1_active_release(struct bus1_active *active,
					wait_queue_head_t *waitq);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#  define bus1_active_init(_active)					\
	({								\
		static struct lock_class_key bus1_active_lock_key;	\
		lockdep_init_map(&(_active)->dep_map, "bus1.active",	\
				 &bus1_active_lock_key, 0);		\
		bus1_active_init_private(_active);			\
	})
#else
#  define bus1_active_init(_active) bus1_active_init_private(_active)
#endif

#endif /* __BUS1_ACTIVE_H */
