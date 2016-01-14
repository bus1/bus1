/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
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
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "active.h"
#include "domain.h"
#include "filesystem.h"
#include "peer.h"
#include "queue.h"
#include "util.h"

enum { /* static inode numbers */
	BUS1_FS_INO_INVALID,
	BUS1_FS_INO_ROOT,
	BUS1_FS_INO_BUS,
	_BUS1_FS_INO_N,
};

static struct file_system_type bus1_fs_type;
static struct inode *bus1_fs_inode_get(struct super_block *sb,
				       unsigned int ino);

static struct bus1_fs_name *bus1_fs_name_new(const char *name,
					     struct bus1_peer *peer)
{
	struct bus1_fs_name *fs_name;
	size_t namelen;

	if (WARN_ON(!peer))
		return ERR_PTR(-EINVAL);

	namelen = strlen(name) + 1;
	if (namelen < 2 || namelen > BUS1_NAME_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	fs_name = kmalloc(sizeof(*fs_name) + namelen, GFP_KERNEL);
	if (!fs_name)
		return ERR_PTR(-ENOMEM);

	fs_name->next = NULL;
	fs_name->peer = peer;
	RB_CLEAR_NODE(&fs_name->rb);
	memcpy(fs_name->name, name, namelen);

	return fs_name;
}

static struct bus1_fs_name *bus1_fs_name_free(struct bus1_fs_name *fs_name)
{
	if (!fs_name)
		return NULL;

	WARN_ON(!RB_EMPTY_NODE(&fs_name->rb));
	kfree_rcu(fs_name, rcu);

	return NULL;
}

static int bus1_fs_name_push(struct bus1_domain *domain,
			     struct bus1_fs_name *fs_name)
{
	struct rb_node *prev, **slot;
	struct bus1_fs_name *iter;
	int v;

	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);

	if (WARN_ON(!fs_name->peer))
		return -EINVAL;

	if (WARN_ON(!RB_EMPTY_NODE(&fs_name->rb)))
		return -EINVAL;

	/* find rb-tree entry and check for possible duplicates first */
	slot = &domain->map_names.rb_node;
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
	rb_link_node_rcu(&fs_name->rb, prev, slot);
	rb_insert_color(&fs_name->rb, &domain->map_names);

	++domain->n_names;
	return 0;
}

static void bus1_fs_name_pop(struct bus1_domain *domain,
			    struct bus1_fs_name *fs_name)
{
	lockdep_assert_held(&domain->lock);
	lockdep_assert_held(&domain->seqcount);

	rb_erase(&fs_name->rb, &domain->map_names);
	RB_CLEAR_NODE(&fs_name->rb);

	--domain->n_names;

	return;
}

static struct bus1_peer *bus1_peer_new(void)
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

static struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
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

void bus1_peer_cleanup(struct bus1_peer *peer,
		       struct bus1_peer_cleanup_context *ctx,
		       bool drop_from_tree)
{
	struct bus1_domain *domain = ctx->domain;
	struct bus1_fs_name *fs_name;
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

	peer_info = rcu_dereference_protected(peer->info, &domain->lock);
	if (peer_info) {
		while ((fs_name = peer->names)) {
			peer->names = peer->names->next;
			bus1_fs_name_pop(domain, fs_name);
			bus1_fs_name_free(fs_name);
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

static struct bus1_peer *bus1_peer_acquire(struct bus1_peer *peer)
{
	if (peer && bus1_active_acquire(&peer->active))
		return peer;
	return NULL;
}

/**
 * bus1_peer_acquire_by_id() - acquire peer by id
 * @domain:		domain to search
 * @id:			id to look for
 *
 * Find a peer handle that is registered under the given id and domain. If
 * found, acquire an active reference and return the handle. If not found, NULL
 * is returned.
 *
 * Return: Active reference to matching handle, or NULL.
 */
struct bus1_peer *
bus1_peer_acquire_by_id(struct bus1_domain *domain, u64 id)
{
	struct bus1_peer *peer, *res = NULL;
	struct rb_node *n;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&domain->seqcount);
		rcu_read_lock();
		n = rcu_dereference(domain->map_peers.rb_node);
		while (n) {
			peer = container_of(n, struct bus1_peer, rb);
			if (id == peer->id) {
				res = bus1_peer_acquire(peer);
				break;
			} else if (id < peer->id) {
				n = rcu_dereference(n->rb_left);
			} else /* if (id > peer->id) */ {
				n = rcu_dereference(n->rb_right);
			}
		}
		rcu_read_unlock();
	} while (!res && read_seqcount_retry(&domain->seqcount, seq));

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
	lockdep_assert_held(&peer->active);

	return rcu_dereference_protected(peer->info, &peer->active);
}

static int bus1_peer_connect_new(struct bus1_peer *peer,
				    struct bus1_domain *domain,
				    struct bus1_cmd_connect *param)
{
	struct bus1_fs_name *fs_name, *names = NULL;
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
	if (!bus1_active_is_new(&peer->active))
		return -EISCONN;

	/*
	 * The domain-reference and peer-lock guarantee that no other
	 * connect, disconnect, or teardown can race us (they wait for us). We
	 * also verified that the peer is NEW. Hence, peer->info must be
	 * NULL. We still verify it, just to be safe.
	 */
	if (WARN_ON(rcu_dereference_protected(peer->info,
					      &domain->active &&
					      &peer->rwlock)))
		return -EISCONN;

	/* allocate new peer_info object */
	peer_info = bus1_peer_info_new(param);
	if (IS_ERR(peer_info))
		return PTR_ERR(peer_info);

	/* allocate names */
	name = param->names;
	remaining = param->size - sizeof(*param);
	while (remaining > 0) {
		n = strnlen(name, remaining);
		if (n == 0 || n == remaining) {
			r = -EMSGSIZE;
			goto error;
		}

		fs_name = bus1_fs_name_new(name, peer);
		if (IS_ERR(fs_name)) {
			r = PTR_ERR(fs_name);
			goto error;
		}

		/* insert into names list */
		fs_name->next = names;
		names = fs_name;

		name += n + 1;
		remaining -= n + 1;
	}

	mutex_lock(&domain->lock);
	write_seqcount_begin(&domain->seqcount);

	/* link into names rbtree */
	for (fs_name = names; fs_name; fs_name = fs_name->next) {
		r = bus1_fs_name_push(domain, fs_name);
		if (r < 0) {
			bus1_fs_name_free(fs_name);
			goto error;
		}
	}

	/* link into peer */
	peer->names = names;

	/* link into rbtree, we know it must be at the tail */
	last = rb_last(&domain->map_peers);
	if (last)
		rb_link_node_rcu(&peer->rb, last, &last->rb_right);
	else
		rb_link_node_rcu(&peer->rb, NULL,
				 &domain->map_peers.rb_node);
	rb_insert_color(&peer->rb, &domain->map_peers);

	/* acquire ID and activate handle */
	peer->id = ++domain->info->peer_ids;
	rcu_assign_pointer(peer->info, peer_info);
	++domain->n_peers;
	bus1_active_activate(&peer->active);

	/* provide ID for caller, pool-size is already set */
	param->unique_id = peer->id;

	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);
	return 0;

error:
	while ((fs_name = names)) {
		names = names->next;
		bus1_fs_name_pop(domain, fs_name);
		bus1_fs_name_free(fs_name);
	}
	peer->names = NULL;

	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);
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
					      &domain->active &&
					      &peer->rwlock);
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

	/* provide information for caller */
	param->unique_id = peer->id;
	param->pool_size = peer_info->pool.size;

	write_seqcount_end(&domain->seqcount);
	mutex_unlock(&domain->lock);

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
					      &domain->active &&
					      &peer->rwlock);
	if (WARN_ON(!peer_info))
		return -ESHUTDOWN;

	param->unique_id = peer->id;
	param->pool_size = peer_info->pool.size;

	return 0;
}

static int bus1_peer_connect(struct bus1_peer *peer,
				struct bus1_domain *domain,
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

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	if (bus1_active_is_deactivated(&peer->active)) {
		/* all fails, if the peer was already disconnected */
		r = -ESHUTDOWN;
	} else if (param->flags & (BUS1_CONNECT_FLAG_PEER |
				   BUS1_CONNECT_FLAG_MONITOR)) {
		/* fresh connect of a new peer */
		r = bus1_peer_connect_new(peer, domain, param);
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

static int bus1_peer_disconnect(struct bus1_peer *peer,
				   struct bus1_domain *domain)
{
	struct bus1_peer_cleanup_context ctx = { .domain = domain, };
	int r;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	/* deactivate and wait for any outstanding operations */
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	/* lock domain and then release the peer */
	mutex_lock(&domain->lock);
	write_seqcount_begin(&domain->seqcount);

	/*
	 * We must not sleep on the peer->waitq, it could deadlock
	 * since we already hold the domain-lock. However, luckily all
	 * peer-releases are locked against the domain, so we wouldn't
	 * gain anything by passing the waitq in.
	 */
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

/*
 * Bus-File
 */

static int bus1_fs_bus_fop_open(struct inode *inode, struct file *file)
{
	struct bus1_domain *domain = inode->i_sb->s_fs_info;
	struct bus1_peer *peer;
	int r;

	if (!bus1_domain_acquire(domain))
		return -ESHUTDOWN;

	peer = bus1_peer_new();
	if (IS_ERR(peer)) {
		r = PTR_ERR(peer);
		goto exit;
	}

	file->private_data = peer;
	r = 0;

exit:
	bus1_domain_release(domain);
	return r;
}

static int bus1_fs_bus_fop_release(struct inode *inode, struct file *file)
{
	struct bus1_domain *domain = inode->i_sb->s_fs_info;
	struct bus1_peer *peer = file->private_data;

	bus1_peer_disconnect(peer, domain);
	bus1_peer_free(peer);

	return 0;
}

static long bus1_fs_bus_fop_ioctl(struct file *file,
				  unsigned int cmd,
				  unsigned long arg,
				  bool is_compat)
{
	struct bus1_domain *domain = file_inode(file)->i_sb->s_fs_info;
	struct bus1_peer *peer = file->private_data;
	long r;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
	case BUS1_CMD_RESOLVE:
		/* lock against domain shutdown */
		if (!bus1_domain_acquire(domain))
			return -ESHUTDOWN;

		if (cmd == BUS1_CMD_CONNECT)
			r = bus1_peer_connect(peer, domain, arg);
		else if (cmd == BUS1_CMD_RESOLVE)
			r = bus1_domain_resolve(domain, arg);
		else
			r = -ENOTTY;

		bus1_domain_release(domain);
		break;

	case BUS1_CMD_DISCONNECT:
		/* no arguments allowed, it behaves like the last close() */
		if (arg != 0)
			return -EINVAL;

		return bus1_peer_disconnect(peer, domain);

	case BUS1_CMD_FREE:
	case BUS1_CMD_TRACK:
	case BUS1_CMD_UNTRACK:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		down_read(&peer->rwlock);
		if (!bus1_peer_acquire(peer)) {
			r = -ESHUTDOWN;
		} else {
			r = bus1_peer_info_ioctl(bus1_peer_dereference(peer),
						 peer->id,
						 domain, domain->info,
						 cmd, arg, is_compat);
			bus1_peer_release(peer);
		}
		up_read(&peer->rwlock);
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
	struct bus1_peer *peer = file->private_data;
	struct bus1_peer_info *peer_info;
	unsigned int mask = 0;

	poll_wait(file, &peer->waitq, wait);

	/*
	 * If the peer is still in state NEW, then CONNECT hasn't been called
	 * and the peer is unused. Return no event at all.
	 * If the peer is not NEW, then CONNECT *was* called. We then check
	 * whether it was deactivated, yet. In that case, the peer is dead
	 * (either via DISCONNECT or domain teardown). Lastly, we dereference
	 * the peer object (which is rcu-protected). It might be NULL during a
	 * racing DISCONNECT (_very_ unlikely, but lets be safe). If it is not
	 * NULL, the peer is life and active, so it is at least writable. Check
	 * if the queue is non-empty, and then also mark it as readable.
	 */
	rcu_read_lock();
	if (!bus1_active_is_new(&peer->active)) {
		peer_info = rcu_dereference(peer->info);
		if (bus1_active_is_deactivated(&peer->active) ||
		    !peer_info) {
			mask = POLLERR | POLLHUP;
		} else {
			mask = POLLOUT | POLLWRNORM;
			if (bus1_queue_peek_rcu(&peer_info->queue))
				mask |= POLLIN | POLLRDNORM;
		}
	}
	rcu_read_unlock();

	return mask;
}

static int bus1_fs_bus_fop_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct bus1_peer *peer = file->private_data;
	struct bus1_pool *pool;
	int r;

	/*
	 * We don't lock peer->rwlock, as it is not needed, and we really
	 * don't want to order it below mmap_sem. Pinning the peer is
	 * sufficient to guarantee the pool is accessible and will not go away.
	 */

	if (!bus1_peer_acquire(peer))
		return -ESHUTDOWN;

	pool = &bus1_peer_dereference(peer)->pool;

	if ((vma->vm_end - vma->vm_start) > pool->size) {
		/* do not allow to map more than the size of the file */
		r = -EFAULT;
	} else if (vma->vm_flags & VM_WRITE) {
		/* deny write access to the pool */
		r = -EPERM;
	} else {
		/* replace the connection file with our shmem file */
		if (vma->vm_file)
			fput(vma->vm_file);

		vma->vm_file = get_file(pool->f);
		vma->vm_flags &= ~VM_MAYWRITE;

		r = pool->f->f_op->mmap(pool->f, vma);
	}

	bus1_peer_release(peer);
	return r;
}

static long bus1_fs_bus_fop_ioctl_native(struct file *file,
					 unsigned int cmd,
					 unsigned long arg)
{
	return bus1_fs_bus_fop_ioctl(file, cmd, arg, false);
}

#ifdef CONFIG_COMPAT
static long bus1_fs_bus_fop_ioctl_compat(struct file *file,
					 unsigned int cmd,
					 unsigned long arg)
{
	return bus1_fs_bus_fop_ioctl(file, cmd, arg, true);
}
#endif

const struct file_operations bus1_fs_bus_fops = {
	.owner =		THIS_MODULE,
	.open =			bus1_fs_bus_fop_open,
	.release =		bus1_fs_bus_fop_release,
	.poll =			bus1_fs_bus_fop_poll,
	.llseek =		noop_llseek,
	.mmap =			bus1_fs_bus_fop_mmap,
	.unlocked_ioctl =	bus1_fs_bus_fop_ioctl_native,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		bus1_fs_bus_fop_ioctl_compat,
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
	struct bus1_domain *domain = file_inode(file)->i_sb->s_fs_info;

	if (!bus1_domain_acquire(domain))
		return -ESHUTDOWN;

	/*
	 * There is only a single directory per mount, hence, it must be the
	 * root directory. Inside of the root directory, we have 3 entries:
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
	bus1_domain_release(domain);
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
	struct bus1_domain *domain = dir->i_sb->s_fs_info;
	struct dentry *old = NULL;
	struct inode *inode;

	if (!bus1_domain_acquire(domain))
		return ERR_PTR(-ESHUTDOWN);

	if (!strcmp(dentry->d_name.name, "bus")) {
		inode = bus1_fs_inode_get(dir->i_sb, BUS1_FS_INO_BUS);
		if (IS_ERR(inode))
			old = ERR_CAST(inode);
		else
			old = d_splice_alias(inode, dentry);
	}

	bus1_domain_release(domain);
	return old;
}

static int bus1_fs_dir_iop_unlink(struct inode *dir, struct dentry *dentry)
{
	struct bus1_domain *domain = dir->i_sb->s_fs_info;

	/*
	 * An unlink() on the `bus' file causes a full, synchronous teardown of
	 * the domain. We only provide this for debug builds, so we can test
	 * the teardown properly. On production builds, it is always rejected
	 * with EPERM (as if .unlink was NULL).
	 */

	if (!strcmp(KBUILD_MODNAME, "bus1"))
		return -EPERM;
	if (strcmp(dentry->d_name.name, "bus"))
		return -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	bus1_domain_teardown(domain);
	clear_nlink(d_inode(dentry));

	return 0;
}

static const struct inode_operations bus1_fs_dir_iops = {
	.permission	= generic_permission,
	.lookup		= bus1_fs_dir_iop_lookup,
	.unlink		= bus1_fs_dir_iop_unlink,
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

	switch (ino) {
	case BUS1_FS_INO_ROOT:
		inode->i_mode = 00755;
		inode->i_mode |= S_IFDIR;
		inode->i_op = &bus1_fs_dir_iops;
		inode->i_fop = &bus1_fs_dir_fops;
		set_nlink(inode, 2);
		break;
	case BUS1_FS_INO_BUS:
		inode->i_mode = 00666;
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
	struct bus1_domain *domain = dentry->d_sb->s_fs_info;

	/*
	 * Revalidation of cached entries is simple. Since all mounts are
	 * static, the only invalidation that can happen is if the whole mount
	 * is deactivated. In that case *anything* is invalid and will never
	 * become valid again.
	 */

	return bus1_active_is_active(&domain->active);
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

	sb->s_flags |= MS_ACTIVE;
	return 0;
}

static void bus1_fs_super_kill(struct super_block *sb)
{
	struct bus1_domain *domain = sb->s_fs_info;

	if (domain)
		bus1_domain_teardown(domain);
	kill_anon_super(sb);
	bus1_domain_free(domain);
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
	struct bus1_domain *domain;
	struct super_block *sb;
	int ret;

	domain = bus1_domain_new();
	if (IS_ERR(domain))
		return ERR_CAST(domain);

	sb = sget(&bus1_fs_type, NULL, bus1_fs_super_set, flags, domain);
	if (IS_ERR(sb)) {
		bus1_domain_teardown(domain);
		bus1_domain_free(domain);
		return ERR_CAST(sb);
	}

	WARN_ON(sb->s_fs_info != domain);
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
