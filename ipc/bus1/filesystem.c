/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "domain.h"
#include "filesystem.h"
#include "main.h"
#include "peer.h"

enum { /* static inode numbers */
	BUS1_FS_INO_INVALID,
	BUS1_FS_INO_ROOT,
	BUS1_FS_INO_BUS,
	_BUS1_FS_INO_N,
};

struct bus1_fs_name {
	struct bus1_fs_name *next;
	struct bus1_fs_peer *fs_peer;
	struct rb_node rb;
	char name[];
};

struct bus1_fs_peer {
	struct rw_semaphore rwlock;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_peer *peer;
	struct bus1_fs_name *names;
	struct rb_node rb;
	u64 id;
};

struct bus1_fs_domain {
	struct rw_semaphore rwlock;
	wait_queue_head_t waitq;
	struct bus1_active active;
	struct bus1_domain *domain;
	size_t n_peers;
	size_t n_names;
	struct rb_root map_peers;
	struct rb_root map_names;
};

static struct file_system_type bus1_fs_type;
static struct inode *bus1_fs_inode_get(struct super_block *sb,
				       unsigned int ino);
static struct bus1_fs_domain *
bus1_fs_domain_acquire(struct bus1_fs_domain *fs_domain);
static struct bus1_fs_domain *
bus1_fs_domain_release(struct bus1_fs_domain *fs_domain);

static struct bus1_fs_name *bus1_fs_name_new(const char *name)
{
	struct bus1_fs_name *fs_name;
	size_t namelen;

	namelen = strlen(name) + 1;
	if (namelen < 2 || namelen > BUS1_NAME_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	fs_name = kmalloc(sizeof(*fs_name) + namelen, GFP_KERNEL);
	if (!fs_name)
		return ERR_PTR(-ENOMEM);

	fs_name->fs_peer = NULL;
	memcpy(fs_name->name, name, namelen);

	return fs_name;
}

static struct bus1_fs_name *bus1_fs_name_free(struct bus1_fs_name *fs_name)
{
	if (!fs_name)
		return NULL;

	/* fs_name->rb might be stray */
	WARN_ON(fs_name->fs_peer);
	WARN_ON(fs_name->next);
	kfree(fs_name);

	return NULL;
}

static int bus1_fs_name_push(struct bus1_fs_domain *fs_domain,
			     struct bus1_fs_peer *fs_peer,
			     struct bus1_fs_name *fs_name)
{
	struct rb_node *prev, **slot;
	struct bus1_fs_name *iter;
	int v;

	lockdep_assert_held(&fs_domain->rwlock); /* write-locked */
	WARN_ON(!RB_EMPTY_NODE(&fs_name->rb));

	/* find rb-tree entry and check for possible duplicates first */
	slot = &fs_domain->map_names.rb_node;
	prev = NULL;
	while (*slot) {
		prev = *slot;
		iter = container_of(prev, struct bus1_fs_name, rb);
		v = strcmp(fs_name->name, iter->name);
		if (!v)
			return -EISNAM;
		else if (v < 0)
			slot = &prev->rb_left;
		else /* if (v > 0) */
			slot = &prev->rb_right;
	}

	/* insert into tree */
	rb_link_node(&fs_name->rb, prev, slot);
	rb_insert_color(&fs_name->rb, &fs_domain->map_names);

	/* insert into peer */
	fs_name->fs_peer = fs_peer;
	fs_name->next = fs_peer->names;
	fs_peer->names = fs_name;

	++fs_domain->n_names;
	return 0;
}

static struct bus1_fs_name *bus1_fs_name_pop(struct bus1_fs_domain *fs_domain,
					     struct bus1_fs_peer *fs_peer,
					     bool drop_from_tree)
{
	struct bus1_fs_name *fs_name;

	lockdep_assert_held(&fs_domain->rwlock); /* write-locked */

	/* pop first entry, if there is one */
	fs_name = fs_peer->names;
	if (!fs_name)
		return NULL;

	/* final teardown is allowed to leave stray data in the tree */
	if (drop_from_tree)
		rb_erase(&fs_name->rb, &fs_domain->map_peers);

	/* remove from peer */
	fs_peer->names = fs_name->next;
	fs_name->next = NULL;
	fs_name->fs_peer = NULL;

	--fs_domain->n_names;
	return fs_name;
}

static struct bus1_fs_peer *bus1_fs_peer_new(void)
{
	struct bus1_fs_peer *fs_peer;

	fs_peer = kmalloc(sizeof(*fs_peer), GFP_KERNEL);
	if (!fs_peer)
		return ERR_PTR(-ENOMEM);

	init_rwsem(&fs_peer->rwlock);
	init_waitqueue_head(&fs_peer->waitq);
	bus1_active_init(&fs_peer->active);
	fs_peer->peer = NULL;
	fs_peer->names = NULL;
	RB_CLEAR_NODE(&fs_peer->rb);
	fs_peer->id = 0;

	return fs_peer;
}

static struct bus1_fs_peer *
bus1_fs_peer_free(struct bus1_fs_peer *fs_peer)
{
	if (!fs_peer)
		return NULL;

	/* fs_peer->rb might be stray */
	WARN_ON(fs_peer->names);
	WARN_ON(fs_peer->peer);
	bus1_active_destroy(&fs_peer->active);
	kfree(fs_peer);

	return NULL;
}

static void bus1_fs_peer_cleanup(struct bus1_fs_peer *fs_peer,
				 struct bus1_fs_domain *fs_domain,
				 bool drop_from_tree)
{
	struct bus1_fs_name *fs_name;

	/*
	 * This function is called by bus1_active_cleanup(), once all active
	 * references to the handle are drained. In that case, we know that
	 * no-one can hold a pointer to the peer, anymore. Hence, we can simply
	 * drop all the peer information and destroy the peer.
	 *
	 * During domain teardown, we avoid dropping peers from the tree, so we
	 * can safely iterate the tree and reset it afterwards.
	 */

	lockdep_assert_held(&fs_domain->rwlock); /* write-locked */

	while ((fs_name = bus1_fs_name_pop(fs_domain, fs_peer, drop_from_tree)))
		bus1_fs_name_free(fs_name);

	if (drop_from_tree)
		rb_erase(&fs_peer->rb, &fs_domain->map_peers);

	--fs_domain->n_peers;
	fs_peer->peer = bus1_peer_free(fs_peer->peer);
}

static void bus1_fs_peer_cleanup_teardown(struct bus1_active *active,
					  void *userdata)
{
	struct bus1_fs_peer *fs_peer = container_of(active,
						    struct bus1_fs_peer,
						    active);

	return bus1_fs_peer_cleanup(fs_peer, userdata, false);
}

static void bus1_fs_peer_cleanup_runtime(struct bus1_active *active,
					 void *userdata)
{
	struct bus1_fs_peer *fs_peer = container_of(active,
						    struct bus1_fs_peer,
						    active);

	return bus1_fs_peer_cleanup(fs_peer, userdata, true);
}

static int bus1_fs_peer_connect_new(struct bus1_fs_peer *fs_peer,
				    struct bus1_fs_domain *fs_domain,
				    struct bus1_cmd_connect *param)
{
	struct bus1_fs_name *fs_name;
	struct bus1_peer *peer;
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

	lockdep_assert_held(&fs_domain->active);
	lockdep_assert_held(&fs_peer->rwlock);

	/* XXX: check param->flags */

	/* allocate new peer object */
	peer = bus1_peer_new(fs_domain->domain, param);
	if (IS_ERR(peer))
		return PTR_ERR(peer);

	down_write(&fs_domain->rwlock);

	/* insert names */
	name = param->names;
	remaining = param->size - sizeof(*param);
	while (remaining > 0) {
		n = strnlen(name, remaining);
		if (n == 0 || n == remaining) {
			r = -EMSGSIZE;
			goto exit;
		}

		fs_name = bus1_fs_name_new(name);
		if (IS_ERR(fs_name)) {
			r = PTR_ERR(fs_name);
			goto exit;
		}

		r = bus1_fs_name_push(fs_domain, fs_peer, fs_name);
		if (r < 0)
			goto exit;
	}

	/* link into rbtree, we know it must be at the tail */
	last = rb_last(&fs_domain->map_peers);
	if (last)
		rb_link_node(&fs_peer->rb, last, &last->rb_right);
	else
		rb_link_node(&fs_peer->rb, NULL,
			     &fs_domain->map_peers.rb_node);
	rb_insert_color(&fs_peer->rb, &fs_domain->map_peers);

	/* acquire ID and activate handle */
	fs_peer->id = ++fs_domain->domain->peer_ids;
	fs_peer->peer = peer;
	++fs_domain->n_peers;
	bus1_active_activate(&fs_peer->active);

	peer = NULL;
	r = 0;

exit:
	if (peer) {
		while ((fs_name = bus1_fs_name_pop(fs_domain, fs_peer, true)))
			bus1_fs_name_free(fs_name);
		bus1_peer_free(peer);
	}
	up_write(&fs_domain->rwlock);
	return r;
}

static int bus1_fs_peer_connect_again(struct bus1_fs_peer *fs_peer,
				      struct bus1_fs_domain *fs_domain,
				      struct bus1_cmd_connect *param)
{
	struct rb_node *last;

	/*
	 * Already connected. Further CONNECT calls are only allowed to
	 * QUERY the current peer or RESET it. Anything else is rejected.
	 */

	lockdep_assert_held(&fs_domain->active);
	lockdep_assert_held(&fs_peer->rwlock);

	if (param->flags & (BUS1_CONNECT_FLAG_PEER |
			    BUS1_CONNECT_FLAG_MONITOR))
		return -EALREADY;

	if (param->size > sizeof(*param) ||
	    param->pool_size != 0 ||
	    param->unique_id != 0)
		return -EINVAL;

	/*
	 * If a RESET is requested, we atomically DISCONNECT and
	 * CONNECT the peer. Luckily, all we have to do is allocate a
	 * new ID and re-add it to the rb-tree. Then we tell the peer
	 * itself to flush any pending data. There might be operations
	 * in-flight, that finish after we reset the peer. All those
	 * operations must be tagged with the old id, though (see
	 * bus1_fs_peer_dereference() for details). Therefore, those
	 * operations can be silently ignored and will be gc'ed later
	 * on if their tag is outdated.
	 */
	if (param->flags & BUS1_CONNECT_FLAG_RESET) {
		down_write(&fs_domain->rwlock);

		/* remove from rb-tree, and change the ID */
		rb_erase(&fs_peer->rb, &fs_domain->map_peers);
		fs_peer->id = ++fs_domain->domain->peer_ids;

		/* insert at the tail again */
		last = rb_last(&fs_domain->map_peers);
		if (last)
			rb_link_node(&fs_peer->rb, last, &last->rb_right);
		else
			rb_link_node(&fs_peer->rb, NULL,
				     &fs_domain->map_peers.rb_node);
		rb_insert_color(&fs_peer->rb, &fs_domain->map_peers);

		up_write(&fs_domain->rwlock);

		/* XXX: reset actual peer, queues, etc. */
	}

	if (param->flags & BUS1_CONNECT_FLAG_QUERY) {
		/* XXX: return unique-id and pool-size to user */
	}

	return 0;
}

static int bus1_fs_peer_connect(struct bus1_fs_peer *fs_peer,
				struct bus1_fs_domain *fs_domain,
				unsigned long arg)
{
	struct bus1_cmd_connect *param;
	int r;

	lockdep_assert_held(&fs_domain->active);

	param = bus1_import_dynamic_ioctl(arg, sizeof(*param));
	if (IS_ERR(param))
		return PTR_ERR(param);

	if (param->flags & ~(BUS1_CONNECT_FLAG_PEER |
			     BUS1_CONNECT_FLAG_MONITOR |
			     BUS1_CONNECT_FLAG_QUERY |
			     BUS1_CONNECT_FLAG_RESET))
		return -EINVAL;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&fs_peer->rwlock);

	if (bus1_active_is_deactivated(&fs_peer->active))
		r = -ESHUTDOWN;
	else if (fs_peer->peer)
		r = bus1_fs_peer_connect_again(fs_peer, fs_domain, param);
	else
		r = bus1_fs_peer_connect_new(fs_peer, fs_domain, param);

	up_write(&fs_peer->rwlock);

	kfree(param);
	return r;
}

static int bus1_fs_peer_disconnect(struct bus1_fs_peer *fs_peer,
				   struct bus1_fs_domain *fs_domain)
{
	int r;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&fs_peer->rwlock);

	/* wait for any outstanding operations */
	bus1_active_drain(&fs_peer->active, &fs_peer->waitq);

	/* lock domain and then release the peer */
	down_write(&fs_domain->rwlock);

	/*
	 * We must not sleep on the fs_peer->waitq, it could deadlock
	 * since we already hold the domain-lock. However, luckily all
	 * peer-releases are locked against the domain, so we wouldn't
	 * gain anything by passing the waitq in.
	 */
	if (bus1_active_cleanup(&fs_peer->active, NULL,
				bus1_fs_peer_cleanup_runtime, fs_domain))
		r = 0;
	else
		r = -ESHUTDOWN;

	up_write(&fs_domain->rwlock);
	up_write(&fs_peer->rwlock);

	return r;
}

static struct bus1_fs_peer *
bus1_fs_peer_acquire(struct bus1_fs_peer *fs_peer)
{
	if (fs_peer && bus1_active_acquire(&fs_peer->active))
		return fs_peer;
	return NULL;
}

/**
 * bus1_fs_peer_acquire_by_id() - acquire peer by id
 * @fs_domain:		domain to search
 * @id:			id to look for
 *
 * Find a peer handle that is registered under the given id and domain. If
 * found, acquire an active reference and return the handle. If not found, NULL
 * is returned.
 *
 * Return: Active reference to matching handle, or NULL.
 */
struct bus1_fs_peer *
bus1_fs_peer_acquire_by_id(struct bus1_fs_domain *fs_domain, u64 id)
{
	struct bus1_fs_peer *fs_peer, *res = NULL;
	struct rb_node *n;

	down_read(&fs_domain->rwlock);
	n = fs_domain->map_peers.rb_node;
	while (n) {
		fs_peer = container_of(n, struct bus1_fs_peer, rb);
		if (id == fs_peer->id) {
			res = bus1_fs_peer_acquire(fs_peer);
			break;
		} else if (id < fs_peer->id) {
			n = n->rb_left;
		} else /* if (id > fs_peer->id) */ {
			n = n->rb_right;
		}
	}
	up_read(&fs_domain->rwlock);

	return res;
}

/**
 * bus1_fs_peer_acquire_by_name() - acquire peer by name
 * @fs_domain:		domain to search
 * @name:		name to look for
 * @out_id:		output storage for ID of found peer, or NULL
 *
 * Find a peer handle that is registered under the given name and domain. If
 * found, acquire an active reference and return the handle (putting the ID of
 * the handle into @out_id, if non-NULL). If not found, NULL is returned and
 * @out_id stays untouched.
 *
 * Return: Active reference to matching handle, or NULL.
 */
struct bus1_fs_peer *
bus1_fs_peer_acquire_by_name(struct bus1_fs_domain *fs_domain,
			     const char *name, u64 *out_id)
{
	struct bus1_fs_peer *res = NULL;
	struct bus1_fs_name *fs_name;
	struct rb_node *n;
	int v;

	down_read(&fs_domain->rwlock);
	n = fs_domain->map_names.rb_node;
	while (n) {
		fs_name = container_of(n, struct bus1_fs_name, rb);
		v = strcmp(name, fs_name->name);
		if (v == 0) {
			res = bus1_fs_peer_acquire(fs_name->fs_peer);
			if (res && out_id)
				*out_id = res->id;
			break;
		} else if (v < 0) {
			n = n->rb_left;
		} else /* if (v > 0) */ {
			n = n->rb_right;
		}
	}
	up_read(&fs_domain->rwlock);

	return res;
}

/**
 * bus1_fs_peer_release() - release an active reference
 * @fs_peer:	handle to release, or NULL
 *
 * This releases an active reference to a peer, acquired previously via one
 * of the lookup functions.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_fs_peer *bus1_fs_peer_release(struct bus1_fs_peer *fs_peer)
{
	if (fs_peer)
		bus1_active_release(&fs_peer->active, &fs_peer->waitq);
	return NULL;
}

/**
 * bus1_fs_peer_dereference() - dereference a peer handle
 * @fs_peer:	handle to dereference
 *
 * Dereference a peer handle to get access to the underlying peer object. This
 * function simply returns the peer-pointer, which then can be accessed
 * directly by the caller. The caller must hold an active reference to the
 * handle, and retain it as long as the peer object is used.
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
 * Return: Pointer to the underlying peer is returned.
 */
struct bus1_peer *bus1_fs_peer_dereference(struct bus1_fs_peer *fs_peer)
{
	lockdep_assert_held(&fs_peer->active);
	return fs_peer->peer;
}

/*
 * Domain Handles
 */

static struct bus1_fs_domain *
bus1_fs_domain_free(struct bus1_fs_domain *fs_domain)
{
	if (!fs_domain)
		return NULL;

	WARN_ON(!RB_EMPTY_ROOT(&fs_domain->map_names));
	WARN_ON(!RB_EMPTY_ROOT(&fs_domain->map_peers));
	WARN_ON(fs_domain->n_names > 0);
	WARN_ON(fs_domain->n_peers > 0);
	WARN_ON(fs_domain->domain);
	bus1_active_destroy(&fs_domain->active);
	kfree(fs_domain);

	return NULL;
}

static struct bus1_fs_domain *bus1_fs_domain_new(void)
{
	struct bus1_fs_domain *fs_domain;
	int r;

	fs_domain = kmalloc(sizeof(*fs_domain), GFP_KERNEL);
	if (!fs_domain)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&fs_domain->waitq);
	bus1_active_init(&fs_domain->active);
	fs_domain->domain = NULL;
	init_rwsem(&fs_domain->rwlock);
	fs_domain->n_peers = 0;
	fs_domain->n_names = 0;
	fs_domain->map_peers = RB_ROOT;
	fs_domain->map_names = RB_ROOT;

	/* domains are implicitly activated during allocation */
	fs_domain->domain = bus1_domain_new();
	if (IS_ERR(fs_domain->domain)) {
		r = PTR_ERR(fs_domain->domain);
		fs_domain->domain = NULL;
		goto error;
	}

	bus1_active_activate(&fs_domain->active);

	return fs_domain;

error:
	bus1_fs_domain_free(fs_domain);
	return ERR_PTR(r);
}

static struct bus1_fs_domain *
bus1_fs_domain_acquire(struct bus1_fs_domain *fs_domain)
{
	if (fs_domain && bus1_active_acquire(&fs_domain->active))
		return fs_domain;
	return NULL;
}

static struct bus1_fs_domain *
bus1_fs_domain_release(struct bus1_fs_domain *fs_domain)
{
	if (fs_domain)
		bus1_active_release(&fs_domain->active, &fs_domain->waitq);
	return NULL;
}

static void bus1_fs_domain_cleanup(struct bus1_active *active, void *userdata)
{
	struct bus1_fs_domain *fs_domain = container_of(active,
							struct bus1_fs_domain,
							active);

	fs_domain->domain = bus1_domain_free(fs_domain->domain);
}

static void bus1_fs_domain_teardown(struct bus1_fs_domain *fs_domain)
{
	struct bus1_fs_peer *fs_peer;
	struct rb_node *n;

	/*
	 * This tears down a whole domain, in a synchronous fashion. This is
	 * non-trivial, as it requires to synchronously drain all peers. So we
	 * first deactivate the domain, which prevents new peers from being
	 * linked to the domain. Then we deactivate all peers, which prevents
	 * any new operation to be entered. We also drain all peers so we're
	 * guaranteed all their operations are done. Then we drain the domain
	 * so no domain reference is left.
	 *
	 * At this point, we know that all our objects are drained. However,
	 * they might not have been cleaned up, yet. Therefore, we write-lock
	 * the domain and now release every peer, lastly followed by a release
	 * of the domain.
	 *
	 * Possible locking scenarios:
	 *
	 *   Peer connect:
	 *     fs_peer.rwlock.write
	 *       fs_domain.rwlock.write
	 *
	 *   Peer disconnect:
	 *     fs_peer.rwlock.write
	 *       fs_peer.active.write
	 *       fs_domain.rwlock.write
	 *         fs_peer.active.try-write
	 *
	 *   Peer lookup:
	 *     fs_peer.rwlock.read
	 *       fs_peer.active.try-read
	 *         fs_domain.rwlock.read        # lock inversion
	 *
	 *   Domain teardown:
	 *     fs_domain.rwlock.read
	 *       fs_peer.active.write
	 *     fs_domain.active.write
	 *     fs_domain.rwlock.write
	 *       fs_peer.active.try-write
	 *     fs_domain.active.try-write
	 *
	 *   There is exactly one lock inversion, which is the peer lookup that
	 *   read-locks the domain while holding a peer reference. Therefore,
	 *   all paths that drain a peer must make sure to never hold a
	 *   write-lock on the domain, but read-locks are fine.
	 */

	bus1_active_deactivate(&fs_domain->active);

	down_read(&fs_domain->rwlock);
	for (n = rb_first(&fs_domain->map_peers); n; n = rb_next(n)) {
		fs_peer = container_of(n, struct bus1_fs_peer, rb);
		bus1_active_deactivate(&fs_peer->active);
		bus1_active_drain(&fs_peer->active, &fs_peer->waitq);
	}
	up_read(&fs_domain->rwlock);

	bus1_active_drain(&fs_domain->active, &fs_domain->waitq);

	down_write(&fs_domain->rwlock);
	for (n = rb_first(&fs_domain->map_peers); n; n = rb_next(n)) {
		fs_peer = container_of(n, struct bus1_fs_peer, rb);

		/*
		 * We must not sleep on the fs_peer->waitq, it could deadlock
		 * since we already hold the domain-lock. However, luckily all
		 * peer-releases are locked against the domain, so we wouldn't
		 * gain anything by passing the waitq in.
		 *
		 * We use a custom cleanup-callback which does the normal peer
		 * cleanup, but leaves the rb-tree untouched. This simplifies
		 * our iterator, as long as we properly reset the tree
		 * afterwards.
		 */
		bus1_active_cleanup(&fs_peer->active, NULL,
				    bus1_fs_peer_cleanup_teardown, fs_domain);
	}
	WARN_ON(fs_domain->n_peers > 0);
	WARN_ON(fs_domain->n_names > 0);
	fs_domain->map_peers = RB_ROOT;
	fs_domain->map_names = RB_ROOT;
	up_write(&fs_domain->rwlock);

	bus1_active_cleanup(&fs_domain->active, &fs_domain->waitq,
			    bus1_fs_domain_cleanup, NULL);
}

static int bus1_fs_domain_resolve(struct bus1_fs_domain *fs_domain,
				  unsigned long arg)
{
	struct bus1_cmd_resolve __user *uparam = (void __user *)arg;
	struct bus1_cmd_resolve *param;
	struct bus1_fs_peer *fs_peer;
	size_t namelen;
	int r;

	lockdep_assert_held(&fs_domain->active);

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

	/* name must be zero-terminated */
	if (param->size <= sizeof(*param) ||
	    param->name[param->size - 1] != 0) {
		r = -EINVAL;
		goto exit;
	}

	/* reject overlong/short names early */
	namelen = param->size - sizeof(*param);
	if (namelen < 2 || namelen > BUS1_NAME_MAX_SIZE) {
		r = -ENXIO;
		goto exit;
	}

	/* lookup peer handle */
	fs_peer = bus1_fs_peer_acquire_by_name(fs_domain, param->name,
					       &param->unique_id);
	if (!fs_peer) {
		r = -ENXIO;
		goto exit;
	}

	if (put_user(param->unique_id, &uparam->unique_id))
		r = -EFAULT;
	else
		r = 0;

	bus1_fs_peer_release(fs_peer);

exit:
	kfree(param);
	return r;
}

/*
 * Bus-File
 */

static int bus1_fs_bus_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_fs_domain *fs_domain = inode->i_sb->s_fs_info;
	struct bus1_fs_peer *fs_peer;
	int r;

	if (!bus1_fs_domain_acquire(fs_domain))
		return -ESHUTDOWN;

	fs_peer = bus1_fs_peer_new();
	if (IS_ERR(fs_peer)) {
		r = PTR_ERR(fs_peer);
		goto exit;
	}

	file->private_data = fs_peer;
	r = 0;

exit:
	bus1_fs_domain_release(fs_domain);
	return r;
}

static int bus1_fs_bus_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_fs_domain *fs_domain = inode->i_sb->s_fs_info;
	struct bus1_fs_peer *fs_peer = file->private_data;

	bus1_fs_peer_disconnect(fs_peer, fs_domain);
	bus1_fs_peer_free(fs_peer);

	return 0;
}

static long bus1_fs_bus_fop_ioctl(struct file *file,
				  unsigned int cmd,
				  unsigned long arg)
{
	struct bus1_fs_domain *fs_domain = file_inode(file)->i_sb->s_fs_info;
	struct bus1_fs_peer *fs_peer = file->private_data;
	long r;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
	case BUS1_CMD_RESOLVE:
		/* lock against domain shutdown */
		if (!bus1_fs_domain_acquire(fs_domain))
			return -ESHUTDOWN;

		if (cmd == BUS1_CMD_CONNECT)
			r = bus1_fs_peer_connect(fs_peer, fs_domain, arg);
		else if (cmd == BUS1_CMD_RESOLVE)
			r = bus1_fs_domain_resolve(fs_domain, arg);
		else
			r = -ENOTTY;

		bus1_fs_domain_release(fs_domain);
		break;

	case BUS1_CMD_DISCONNECT:
		/* no arguments allowed, it behaves like the last close() */
		if (arg != 0)
			return -EINVAL;

		return bus1_fs_peer_disconnect(fs_peer, fs_domain);

	case BUS1_CMD_FREE:
	case BUS1_CMD_TRACK:
	case BUS1_CMD_UNTRACK:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		down_read(&fs_peer->rwlock);
		if (!bus1_fs_peer_acquire(fs_peer)) {
			r = -ESHUTDOWN;
		} else {
			r = bus1_peer_ioctl(fs_peer->peer, fs_domain,
					    cmd, arg);
			bus1_fs_peer_release(fs_peer);
		}
		up_read(&fs_peer->rwlock);
		break;

	default:
		/* handle ENOTTY on the top-level, so user-space can probe */
		return -ENOTTY;
	}

	return r;
}

static unsigned int bus1_fs_bus_fop_poll(struct file *file,
					 struct poll_table_struct *wait)
{
	struct bus1_fs_peer *fs_peer = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	if (bus1_active_is_active(&fs_peer->active)) {
		poll_wait(file, &fs_peer->waitq, wait);
		if (0) /* XXX: is-readable */
			mask |= POLLIN | POLLRDNORM;
	} else {
		mask = POLLERR | POLLHUP;
	}

	return mask;
}

static int bus1_fs_bus_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* XXX: forward to peer */
	return -EINVAL;
}

static const struct file_operations bus1_fs_bus_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fs_bus_fop_open,
	.release =		bus1_fs_bus_fop_release,
	.poll =			bus1_fs_bus_fop_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	bus1_fs_bus_fop_ioctl,
	.mmap =			bus1_fs_bus_fop_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		bus1_fs_bus_fop_ioctl,
#endif
};

static const struct inode_operations bus1_fs_bus_iops = {
	.permission	= generic_permission,
};

/*
 * Directories
 */

static int bus1_fs_dir_fop_iterate(struct file *file, struct dir_context *ctx)
{
	struct bus1_fs_domain *fs_domain = file_inode(file)->i_sb->s_fs_info;

	if (!bus1_fs_domain_acquire(fs_domain))
		return -ESHUTDOWN;

	/*
	 * There is only a single directory per mount, hence, it must be the
	 * root directory. Inside of the root directory, we have 3 entires:
	 * The 2 standard directories (`.', `..') and one fixed entry called
	 * `bus', which is the entry point for new peers.
	 */
	WARN_ON(file->f_path.dentry != file->f_path.dentry->d_sb->s_root);

	if (!dir_emit_dots(file, ctx))
		goto exit;
	if (ctx->pos == 2) {
		if (!dir_emit(ctx, "bus", 3, BUS1_FS_INO_BUS, DT_REG))
			goto exit;
		ctx->pos = 3;
	}

	ctx->pos = INT_MAX;

exit:
	bus1_fs_domain_release(fs_domain);
	return 0;
}

static loff_t bus1_fs_dir_fop_llseek(struct file *file,
				     loff_t offset,
				     int whence)
{
	struct inode *inode = file_inode(file);
	loff_t r;

	/* protect f_off against fop_iterate */
	mutex_lock(&inode->i_mutex);
	r = generic_file_llseek(file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	return r;
}

static const struct file_operations bus1_fs_dir_fops = {
	.read		= generic_read_dir,
	.iterate	= bus1_fs_dir_fop_iterate,
	.llseek		= bus1_fs_dir_fop_llseek,
};

static struct dentry *bus1_fs_dir_iop_lookup(struct inode *dir,
					     struct dentry *dentry,
					     unsigned int flags)
{
	struct bus1_fs_domain *fs_domain = dir->i_sb->s_fs_info;
	struct dentry *old = NULL;
	struct inode *inode;

	if (!bus1_fs_domain_acquire(fs_domain))
		return ERR_PTR(-ESHUTDOWN);

	if (!strcmp(dentry->d_name.name, "bus")) {
		inode = bus1_fs_inode_get(dir->i_sb, BUS1_FS_INO_BUS);
		if (IS_ERR(inode))
			old = ERR_CAST(inode);
		else
			old = d_splice_alias(inode, dentry);
	}

	bus1_fs_domain_release(fs_domain);
	return old;
}

static const struct inode_operations bus1_fs_dir_iops = {
	.permission	= generic_permission,
	.lookup		= bus1_fs_dir_iop_lookup,
};

/*
 * Inodes
 */

static struct inode *bus1_fs_inode_get(struct super_block *sb,
				       unsigned int ino)
{
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	inode->i_mapping->a_ops = &empty_aops;
	inode->i_atime = inode->i_ctime = inode->i_mtime = CURRENT_TIME;

	/* XXX: default permissions? (uid/gid is root) */
	inode->i_mode = S_IALLUGO;

	switch (ino) {
	case BUS1_FS_INO_ROOT:
		inode->i_mode |= S_IFDIR;
		inode->i_op = &bus1_fs_dir_iops;
		inode->i_fop = &bus1_fs_dir_fops;
		set_nlink(inode, 2);
		break;
	case BUS1_FS_INO_BUS:
		inode->i_mode |= S_IFREG;
		inode->i_op = &bus1_fs_bus_iops;
		inode->i_fop = &bus1_fs_bus_fops;
		break;
	default:
		WARN(1, "populating invalid inode\n");
		break;
	}

	unlock_new_inode(inode);
	return inode;
}

/*
 * Superblocks
 */

static int bus1_fs_super_dop_revalidate(struct dentry *dentry,
					unsigned int flags)
{
	struct bus1_fs_domain *fs_domain = dentry->d_sb->s_fs_info;

	/*
	 * Revalidation of cached entries is simple. Since all mounts are
	 * static, the only invalidation that can happen is if the whole mount
	 * is deactivated. In that case *anything* is invalid and will never
	 * become valid again.
	 */

	return bus1_active_is_active(&fs_domain->active);
}

static const struct dentry_operations bus1_fs_super_dops = {
	.d_revalidate	= bus1_fs_super_dop_revalidate,
};

static const struct super_operations bus1_fs_super_sops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

static int bus1_fs_super_fill(struct super_block *sb)
{
	struct bus1_fs_domain *fs_domain = sb->s_fs_info;
	struct inode *inode;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = BUS1_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &bus1_fs_super_sops;
	sb->s_d_op = &bus1_fs_super_dops;
	sb->s_time_gran = 1;

	inode = bus1_fs_inode_get(sb, BUS1_FS_INO_ROOT);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		/* d_make_root iput()s the inode on failure */
		return -ENOMEM;
	}

	bus1_active_activate(&fs_domain->active);
	sb->s_flags |= MS_ACTIVE;
	return 0;
}

static void bus1_fs_super_kill(struct super_block *sb)
{
	struct bus1_fs_domain *fs_domain = sb->s_fs_info;

	if (fs_domain)
		bus1_fs_domain_teardown(fs_domain);
	kill_anon_super(sb);
	bus1_fs_domain_free(fs_domain);
}

static int bus1_fs_super_set(struct super_block *sb, void *data)
{
	int ret;

	ret = set_anon_super(sb, data);
	if (!ret)
		sb->s_fs_info = data;

	return ret;
}

static struct dentry *bus1_fs_super_mount(struct file_system_type *fs_type,
					  int flags,
					  const char *dev_name,
					  void *data)
{
	struct bus1_fs_domain *fs_domain;
	struct super_block *sb;
	int ret;

	fs_domain = bus1_fs_domain_new();
	if (IS_ERR(fs_domain))
		return ERR_CAST(fs_domain);

	sb = sget(&bus1_fs_type, NULL, bus1_fs_super_set, flags, fs_domain);
	if (IS_ERR(sb)) {
		bus1_fs_domain_teardown(fs_domain);
		bus1_fs_domain_free(fs_domain);
		return ERR_CAST(sb);
	}

	WARN_ON(sb->s_fs_info != fs_domain);
	WARN_ON(sb->s_root);

	ret = bus1_fs_super_fill(sb);
	if (ret < 0) {
		/* calls into ->kill_sb() when done */
		deactivate_locked_super(sb);
		return ERR_PTR(ret);
	}

	return dget(sb->s_root);
}

static struct file_system_type bus1_fs_type = {
	.name		= KBUILD_MODNAME "fs",
	.owner		= THIS_MODULE,
	.mount		= bus1_fs_super_mount,
	.kill_sb	= bus1_fs_super_kill,
	.fs_flags	= FS_USERNS_MOUNT,
};

/**
 * bus1_fs_init() - register filesystem
 *
 * This registers a filesystem with the VFS layer. The filesystem is called
 * `KBUILD_MODNAME "fs"', which usually resolves to `bus1fs'. The nameing
 * scheme allows to set KBUILD_MODNAME to `bus2' and you will get an
 * independent filesystem for developers, named `bus2fs'.
 *
 * Each mount of the bus1fs filesystem has an bus1_ns attached. Operations
 * on this mount will only affect the attached namespace. On each mount a new
 * namespace is automatically created and used for this mount exclusively.
 * If you want to share a namespace across multiple mounts, you need to
 * bind-mount it.
 *
 * Mounts of bus1fs (with a different namespace each) are unrelated to each
 * other and will never have any effect on any namespace but their own.
 *
 * Return: 0 on success, negative error otherwise.
 */
int __init bus1_fs_init(void)
{
	return register_filesystem(&bus1_fs_type);
}

/**
 * bus1_fs_exit() - unregister filesystem
 *
 * This does the reverse to bus1_fs_init(). It unregisters the bus1
 * filesystem from VFS and cleans up any allocated resources.
 */
void __exit bus1_fs_exit(void)
{
	unregister_filesystem(&bus1_fs_type);
}
