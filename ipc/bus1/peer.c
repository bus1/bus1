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
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid_namespace.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "main.h"
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "user.h"
#include "util.h"

static void bus1_peer_info_reset(struct bus1_peer_info *peer_info, bool final)
{
	struct bus1_queue_node *node;
	struct bus1_message *message;
	size_t n_slices;
	LIST_HEAD(list);

	bus1_handle_flush_all(peer_info, final);
	bus1_queue_flush(&peer_info->queue, &list, final);

	mutex_lock(&peer_info->lock);
	bus1_pool_flush(&peer_info->pool, &n_slices);
	bus1_user_quota_release_slices(peer_info, n_slices);
	mutex_unlock(&peer_info->lock);

	while ((node = list_first_entry_or_null(&list, struct bus1_queue_node,
						link))) {
		list_del(&node->link);
		RB_CLEAR_NODE(&node->rb);

		switch (bus1_queue_node_get_type(node)) {
		case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
			message = bus1_message_from_node(node);
			/*
			 * If a message was either never staged, or it was fully
			 * committed, we know that a possible transaction is
			 * done. Hence, we are responsible of cleanup. In all
			 * other cases, the transaction is still ongoing and
			 * will notify the queue-removal and cleanup the node.
			 */
			if (bus1_queue_node_is_committed(node) ||
			    !bus1_queue_node_get_timestamp(node)) {
				bus1_message_deallocate(message, peer_info);
				bus1_message_flush(message, peer_info);
			}
			bus1_message_unref(message);
			break;
		case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
		case BUS1_QUEUE_NODE_HANDLE_RELEASE:
			bus1_handle_unref_queued(node);
			break;
		default:
			WARN(1, "Invalid queue-node type");
			break;
		}
	}
}

static struct bus1_peer_info *
bus1_peer_info_free(struct bus1_peer_info *peer_info)
{
	if (!peer_info)
		return NULL;

	bus1_peer_info_reset(peer_info, true);

	bus1_queue_destroy(&peer_info->queue);
	bus1_pool_destroy(&peer_info->pool);
	bus1_user_quota_destroy(&peer_info->quota);

	peer_info->user = bus1_user_unref(peer_info->user);
	put_pid_ns(peer_info->pid_ns);
	put_cred(peer_info->cred);

	WARN_ON(peer_info->n_bytes);
	WARN_ON(peer_info->n_slices);
	WARN_ON(peer_info->n_handles);
	WARN_ON(peer_info->n_fds);
	WARN_ON(!RB_EMPTY_ROOT(&peer_info->map_handles_by_node));
	WARN_ON(!RB_EMPTY_ROOT(&peer_info->map_handles_by_id));

	/*
	 * Make sure the object is freed in a delayed-manner. Some
	 * embedded members (like the queue) must be accessible for an entire
	 * rcu read-side critical section.
	 */
	kfree_rcu(peer_info, rcu);

	return NULL;
}

static struct bus1_peer_info *bus1_peer_info_new(wait_queue_head_t *waitq)
{
	struct bus1_peer_info *peer_info;
	int r;

	peer_info = kmalloc(sizeof(*peer_info), GFP_KERNEL);
	if (!peer_info)
		return ERR_PTR(-ENOMEM);

	mutex_init(&peer_info->lock);
	peer_info->cred = get_cred(current_cred());
	peer_info->pid_ns = get_pid_ns(task_active_pid_ns(current));
	peer_info->user = NULL;
	bus1_user_quota_init(&peer_info->quota);
	peer_info->pool = BUS1_POOL_NULL;
	bus1_queue_init(&peer_info->queue, waitq);
	peer_info->map_handles_by_id = RB_ROOT;
	peer_info->map_handles_by_node = RB_ROOT;
	seqcount_init(&peer_info->seqcount);
	peer_info->handle_ids = 0;
	peer_info->n_bytes = 0;
	peer_info->n_slices = 0;
	peer_info->n_handles = 0;
	peer_info->n_fds = 0;
	peer_info->max_bytes = -1;
	peer_info->max_slices = -1;
	peer_info->max_handles = -1;
	peer_info->max_fds = -1;

	peer_info->user = bus1_user_ref_by_uid(peer_info->cred->uid);
	if (IS_ERR(peer_info->user)) {
		r = PTR_ERR(peer_info->user);
		peer_info->user = NULL;
		goto error;
	}

	r = bus1_pool_create_for_peer(peer_info, BUS1_POOL_SLICE_SIZE_MAX);
	if (r < 0)
		goto error;

	return peer_info;

error:
	bus1_peer_info_free(peer_info);
	return ERR_PTR(r);
}

/**
 * bus1_peer_new() - allocate new peer
 *
 * Allocate a new peer. The peer is *not* activated, nor linked into any
 * context. The caller owns the only pointer to the new peer.
 *
 * Return: Pointer to peer, ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(void)
{
	static atomic64_t bus1_peer_ids = ATOMIC64_INIT(0);
	struct bus1_peer *peer;

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&peer->waitq);
	bus1_active_init(&peer->active);
	rcu_assign_pointer(peer->info, NULL);
	peer->id = atomic64_inc_return(&bus1_peer_ids);
	peer->debugdir = NULL;

	if (!IS_ERR_OR_NULL(bus1_debugdir)) {
		char idstr[17];

		snprintf(idstr, sizeof(idstr), "%llx", peer->id);

		peer->debugdir = debugfs_create_dir(idstr, bus1_debugdir);
		if (!peer->debugdir) {
			pr_err("cannot create debugfs dir for peer %llx\n",
			       peer->id);
		} else if (!IS_ERR_OR_NULL(peer->debugdir)) {
			bus1_debugfs_create_atomic_x("active", S_IRUGO,
						     peer->debugdir,
						     &peer->active.count);
		}
	}

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

	WARN_ON(rcu_access_pointer(peer->info));
	debugfs_remove_recursive(peer->debugdir);
	bus1_active_destroy(&peer->active);
	kfree_rcu(peer, rcu);

	return NULL;
}

static void bus1_peer_cleanup(struct bus1_active *active, void *userdata)
{
	struct bus1_peer *peer = container_of(active, struct bus1_peer, active);
	struct bus1_peer_info *peer_info;

	/*
	 * bus1_active guarantees that this function is called exactly once,
	 * and that it cannot race bus1_peer_connect(). It is therefore safe
	 * to access the info obect without any locking.
	 */
	peer_info = rcu_dereference_raw(peer->info);
	rcu_assign_pointer(peer->info, NULL);

	bus1_peer_info_free(peer_info);
}

/**
 * bus1_peer_disconnect() - disconnect peer
 * @peer:		peer to operate on
 *
 * This tears down a peer synchronously. It first marks the peer as deactivated,
 * waits for all outstanding operations to finish, and eventually releases the
 * linked peer_info object.
 *
 * It is perfectly safe to call this function multiple times, even in parallel.
 * It is guaranteed to block *until* the peer is fully torn down, regardless
 * whether this was the call to tear it down, or not.
 *
 * Return: 0 on success, negative error code if already torn down.
 */
int bus1_peer_disconnect(struct bus1_peer *peer)
{
	/* deactivate and wait for any outstanding operations */
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	if (!bus1_active_cleanup(&peer->active, &peer->waitq,
				 bus1_peer_cleanup, NULL))
		return -ESHUTDOWN;

	return 0;
}

/**
 * bus1_peer_connect() - connect peer
 * @peer:		peer to operate on
 *
 * This connects a peer. It first creates the linked peer_info object and then
 * markes the peer as active.
 *
 * The caller must make sure this function is called only once.
 *
 * Return: 0 on success, negative error code if already torn down.
 */
int bus1_peer_connect(struct bus1_peer *peer)
{
	struct bus1_peer_info *peer_info;

	if (WARN_ON(!bus1_active_is_new(&peer->active)))
		return -ENOTRECOVERABLE;

	peer_info = bus1_peer_info_new(&peer->waitq);
	if (IS_ERR(peer_info))
		return PTR_ERR(peer_info);

	rcu_assign_pointer(peer->info, peer_info);

	bus1_active_activate(&peer->active);

	return 0;
}

static int bus1_peer_ioctl_init(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_cmd_peer_init param;
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_INIT) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) || unlikely(param.max_bytes == 0) ||
	    unlikely(param.max_slices == 0))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	mutex_lock(&peer_info->lock);
	peer_info->max_bytes = param.max_bytes;
	peer_info->max_slices = param.max_slices;
	peer_info->max_handles = param.max_handles;
	peer_info->max_fds = param.max_fds;
	mutex_unlock(&peer_info->lock);

	return 0;
}

static int bus1_peer_ioctl_query(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_cmd_peer_init __user *uparam = (void __user  *) arg;
	struct bus1_cmd_peer_init param;
	struct bus1_peer_info *peer_info;
	u64 max_bytes, max_slices, max_handles, max_fds;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_QUERY) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) || unlikely(param.max_bytes) ||
	    unlikely(param.max_slices) || unlikely(param.max_handles) ||
	    unlikely(param.max_fds))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	mutex_lock(&peer_info->lock);
	max_bytes = peer_info->max_bytes;
	max_slices = peer_info->max_slices;
	max_handles = peer_info->max_handles;
	max_fds = peer_info->max_fds;
	mutex_unlock(&peer_info->lock);

	if (put_user(max_bytes, &uparam->max_bytes) ||
	    put_user(max_slices, &uparam->max_slices) ||
	    put_user(max_handles, &uparam->max_handles) ||
	    put_user(max_fds, &uparam->max_fds))
		return -EFAULT;

	return 0;
}

static int bus1_peer_ioctl_reset(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_cmd_peer_reset param;
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_RESET) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	/* flush everything, but keep persistent nodes */
	bus1_peer_info_reset(peer_info, false);

	return 0;
}

static int bus1_peer_ioctl_clone(struct bus1_peer *peer,
			  struct file *peer_file,
			  unsigned long arg)
{
	struct bus1_cmd_peer_clone __user *uparam = (void __user *) arg;
	struct bus1_cmd_peer_clone param;
	struct bus1_peer_info *peer_info;
	struct bus1_peer *clone = NULL;
	struct file *clone_file = NULL;
	int r, fd;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_CLONE) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) ||
	    unlikely(param.child_handle != BUS1_HANDLE_INVALID) ||
	    unlikely(param.fd != (u64)-1))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		r = fd;
		goto error;
	}

	clone = bus1_peer_new();
	if (IS_ERR(clone)) {
		r = PTR_ERR(clone);
		clone = NULL;
		goto error;
	}

	clone_file = bus1_clone_file(peer_file);
	if (IS_ERR(clone_file)) {
		r = PTR_ERR(clone_file);
		clone_file = NULL;
		goto error;
	}
	clone_file->private_data = clone; /* released via f_op->release() */

	r = bus1_peer_connect(clone);
	if (r < 0)
		goto error;

	WARN_ON(!bus1_peer_acquire(clone));

	/* pass handle from parent to child, allocating node if necessary */
	r = bus1_handle_pair(peer, clone, &param.parent_handle,
			     &param.child_handle);
	if (r < 0) {
		bus1_peer_release(clone);
		goto error;
	}

	fd_install(fd, clone_file); /* consumes file reference */
	bus1_peer_release(clone);

	if (put_user(param.parent_handle, &uparam->parent_handle) ||
	    put_user(param.child_handle, &uparam->child_handle) ||
	    put_user(fd, &uparam->fd))
		return -EFAULT; /* We don't care, keep what we did */

	return 0;

error:
	if (clone_file)
		fput(clone_file);
	else
		bus1_peer_free(clone);
	if (fd >= 0)
		put_unused_fd(fd);
	return r;
}

static int bus1_peer_ioctl_node_destroy(struct bus1_peer *peer,
					unsigned long arg)
{
	u64 id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_NODE_DESTROY) != sizeof(id));

	if (get_user(id, (const u64 __user *)arg))
		return -EFAULT;

	/* returns >= 0 on success, and > 0 in case @id was modified */
	r = bus1_node_destroy_by_id(peer, &id);
	if (r < 0)
		return r;
	if (r > 0 && put_user(id, (u64 __user *)arg))
		return -EFAULT;

	return 0;
}

static int bus1_peer_ioctl_handle_release(struct bus1_peer *peer,
					  unsigned long arg)
{
	u64 id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) != sizeof(id));

	if (get_user(id, (const u64 __user *)arg))
		return -EFAULT;

	/* returns >= 0 on success, and > 0 in case @id was modified */
	r = bus1_handle_release_by_id(peer, &id);
	if (r < 0)
		return r;
	if (r > 0 && put_user(id, (u64 __user *)arg))
		return -EFAULT;

	return 0;
}

static int bus1_peer_ioctl_slice_release(struct bus1_peer *peer,
					 unsigned long arg)
{
	struct bus1_peer_info *peer_info;
	u64 offset;
	int r;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) != sizeof(offset));

	if (get_user(offset, (const u64 __user *)arg))
		return -EFAULT;

	peer_info = bus1_peer_dereference(peer);

	mutex_lock(&peer_info->lock);
	r = bus1_pool_release_user(&peer_info->pool, offset);
	mutex_unlock(&peer_info->lock);
	if (r < 0)
		return r;

	bus1_user_quota_release_slices(peer_info, 1);

	return 0;
}

static int bus1_peer_ioctl_send(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_transaction *transaction = NULL;
	/* Use a stack-allocated buffer for the transaction object if it fits */
	u8 buf[512];
	struct bus1_cmd_send param;
	u64 __user *ptr_dest;
	size_t i;
	int r;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SEND) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_SEND_FLAG_CONTINUE |
				     BUS1_SEND_FLAG_SEED)))
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
	    unlikely(param.ptr_handles !=
		     (u64)(unsigned long)param.ptr_handles) ||
	    unlikely(param.ptr_fds !=
		     (u64)(unsigned long)param.ptr_fds))
		return -EFAULT;

	ptr_dest = (u64 __user *)(unsigned long)param.ptr_destinations;

	transaction = bus1_transaction_new_from_user(buf, sizeof(buf), peer,
						     &param);
	if (IS_ERR(transaction))
		return PTR_ERR(transaction);

	if (param.flags & BUS1_SEND_FLAG_SEED) { /* Special-case: set seed */
		if (unlikely((param.flags & BUS1_SEND_FLAG_CONTINUE) ||
			     param.n_destinations)) {
			r = -EINVAL;
			goto exit;
		}

		r = bus1_transaction_commit_seed(transaction);
		if (r < 0)
			goto exit;

	} else if (param.n_destinations == 1) { /* Fastpath: unicast */
		r = bus1_transaction_commit_for_id(transaction,
						   ptr_dest);
		if (r < 0)
			goto exit;

	} else { /* Slowpath: any message */
		for (i = 0; i < param.n_destinations; ++i) {
			r = bus1_transaction_instantiate_for_id(transaction,
								ptr_dest + i);
			if (r < 0)
				goto exit;
		}

		r = bus1_transaction_commit(transaction);
		if (r < 0)
			goto exit;
	}

	r = 0;

exit:
	bus1_transaction_free(transaction, buf);
	return r;
}

static struct bus1_queue_node *
bus1_peer_queue_peek(struct bus1_peer_info *peer_info,
		     struct bus1_cmd_recv *param,
		     bool drop)
{
	struct bus1_queue_node *node;
	struct bus1_message *message = NULL;
	int r;

	/*
	 * Any dequeue operation might be raced by a RESET or similar message
	 * removal. Therefore, we rely on the peer-lock to be held for the
	 * entire time of this dequeue operation. This guarantees that any
	 * racing RESET cannot release message resources and as such blocks on
	 * the dequeue operation. Hence, we can safely access the message
	 * without requiring the queue to stay locked.
	 */

	lockdep_assert_held(&peer_info->lock);

	node = bus1_queue_peek(&peer_info->queue,
			       !!(param->flags & BUS1_RECV_FLAG_SEED));
	if (node) {
		if (bus1_queue_node_get_type(node) ==
					BUS1_QUEUE_NODE_MESSAGE_NORMAL) {
			message = bus1_message_from_node(node);

			r = bus1_message_install(message, peer_info);
			if (r < 0) {
				bus1_message_unref(message);
				return ERR_PTR(r);
			}
		}

		if (drop)
			bus1_queue_remove(&peer_info->queue, node);
	}

	if (drop)
		param->n_dropped = bus1_queue_flush_dropped(&peer_info->queue);
	else
		param->n_dropped = bus1_queue_peek_dropped(&peer_info->queue);

	return node;
}

static int bus1_peer_dequeue(struct bus1_peer_info *peer_info,
			     struct bus1_cmd_recv *param)
{
	struct bus1_message *message = NULL;
	struct bus1_queue_node *node;
	int r;

	mutex_lock(&peer_info->lock);

	node = bus1_peer_queue_peek(peer_info, param, true);
	if (IS_ERR_OR_NULL(node)) {
		r = PTR_ERR(node);
		goto exit;
	}

	switch (bus1_queue_node_get_type(node)) {
	case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
		message = bus1_message_from_node(node);
		bus1_pool_publish(&peer_info->pool, message->slice);
		bus1_message_dequeue(message, peer_info);
		param->type = BUS1_MSG_DATA;
		memcpy(&param->data, &message->data, sizeof(param->data));
		break;

	case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
		param->type = BUS1_MSG_NODE_DESTROY;
		param->node_destroy.handle = bus1_handle_unref_queued(node);
		break;

	case BUS1_QUEUE_NODE_HANDLE_RELEASE:
		param->type = BUS1_MSG_NODE_RELEASE;
		param->node_release.handle = bus1_handle_unref_queued(node);
		break;

	default:
		WARN(1, "Invalid queue-node type");
		r = -ENOTRECOVERABLE;
		break;
	}

	r = 0;

exit:
	mutex_unlock(&peer_info->lock);
	if (message) {
		bus1_message_flush(message, peer_info);
		bus1_message_unref(message);
	}
	return r;
}

static int bus1_peer_peek(struct bus1_peer_info *peer_info,
			  struct bus1_cmd_recv *param)
{
	struct bus1_queue_node *node;
	struct bus1_message *message;
	int r;

	mutex_lock(&peer_info->lock);

	node = bus1_peer_queue_peek(peer_info, param, false);
	if (IS_ERR_OR_NULL(node)) {
		r = PTR_ERR(node);
		goto exit;
	}

	switch (bus1_queue_node_get_type(node)) {
	case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
		message = bus1_message_from_node(node);
		bus1_pool_publish(&peer_info->pool, message->slice);
		param->type = BUS1_MSG_DATA;
		memcpy(&param->data, &message->data, sizeof(param->data));
		bus1_message_unref(message);
		break;

	case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
		param->type = BUS1_MSG_NODE_DESTROY;
		param->node_destroy.handle = bus1_handle_unref_queued(node);
		break;

	case BUS1_QUEUE_NODE_HANDLE_RELEASE:
		param->type = BUS1_MSG_NODE_RELEASE;
		param->node_release.handle = bus1_handle_unref_queued(node);
		break;

	default:
		WARN(1, "Invalid queue-node type");
		break;
	}

	r = 0;

exit:
	mutex_unlock(&peer_info->lock);
	return r;
}

static int bus1_peer_ioctl_recv(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_peer_info *peer_info;
	struct bus1_cmd_recv param;
	int r;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_RECV) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_RECV_FLAG_PEEK |
				     BUS1_RECV_FLAG_SEED) ||
		     param.type != BUS1_MSG_NONE ||
		     param.n_dropped != 0))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	if (param.flags & BUS1_RECV_FLAG_PEEK)
		r = bus1_peer_peek(peer_info, &param);
	else
		r = bus1_peer_dequeue(peer_info, &param);

	if (r < 0)
		return r;
	if (!param.n_dropped && param.type == BUS1_MSG_NONE)
		return -EAGAIN;

	return copy_to_user((void __user *)arg,
			    &param, sizeof(param)) ? -EFAULT : 0;
}

/**
 * bus1_peer_ioctl() - handle peer ioctl
 * @peer:		peer to work on
 * @peer_file:		underlying file of @peer
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on the passed peer. The caller must
 * hold an active reference to @peer.
 *
 * This only handles the runtime ioctls. Setup and teardown must be called
 * directly.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl(struct bus1_peer *peer,
		    struct file *peer_file,
		    unsigned int cmd,
		    unsigned long arg)
{
	lockdep_assert_held(&peer->active);

	switch (cmd) {
	case BUS1_CMD_PEER_INIT:
		return bus1_peer_ioctl_init(peer, arg);
	case BUS1_CMD_PEER_QUERY:
		return bus1_peer_ioctl_query(peer, arg);
	case BUS1_CMD_PEER_RESET:
		return bus1_peer_ioctl_reset(peer, arg);
	case BUS1_CMD_PEER_CLONE:
		return bus1_peer_ioctl_clone(peer, peer_file, arg);
	case BUS1_CMD_NODE_DESTROY:
		return bus1_peer_ioctl_node_destroy(peer, arg);
	case BUS1_CMD_HANDLE_RELEASE:
		return bus1_peer_ioctl_handle_release(peer, arg);
	case BUS1_CMD_SLICE_RELEASE:
		return bus1_peer_ioctl_slice_release(peer, arg);
	case BUS1_CMD_SEND:
		return bus1_peer_ioctl_send(peer, arg);
	case BUS1_CMD_RECV:
		return bus1_peer_ioctl_recv(peer, arg);
	}

	return -ENOTTY;
}
