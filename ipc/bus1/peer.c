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

static struct bus1_message *
bus1_peer_info_flush(struct bus1_peer_info *peer_info)
{
	struct bus1_queue_node *node, *t;
	struct bus1_message *message, *list = NULL;

	/*
	 * This flushes all messages from a peer-queue. The parent peer is
	 * expected to be locked by the caller.
	 * We first lock the queue and detach all messages from it. In case
	 * some cleanup of the message is needed, we remember it in a temporary
	 * list. Once the queue is flushed, we unlock it and perform the
	 * cleanup on each message. The list is then returned to the caller in
	 * case further cleanups are needed with the peer unlocked.
	 */

	lockdep_assert_held(&peer_info->lock);

	mutex_lock(&peer_info->qlock);
	rbtree_postorder_for_each_entry_safe(node, t,
					     &peer_info->queue.messages, rb) {
		switch (bus1_queue_node_get_type(node)) {
		case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
		case BUS1_QUEUE_NODE_MESSAGE_SILENT:
			message = bus1_message_from_node(node);
			RB_CLEAR_NODE(&node->rb); /* mark as dropped */
			if (bus1_queue_node_is_committed(node)) {
				message->transaction.next = list;
				list = message;
			}
			break;
		case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
		case BUS1_QUEUE_NODE_HANDLE_RELEASE:
			RB_CLEAR_NODE(&node->rb);
			bus1_handle_from_queue(node, peer_info, true);
			break;
		default:
			WARN(1, "Invalid queue-node type");
			break;
		}
	}
	bus1_queue_post_flush(&peer_info->queue);
	mutex_unlock(&peer_info->qlock);

	for (message = list; message; message = message->transaction.next)
		bus1_message_deallocate(message, peer_info);

	return list;
}

static void bus1_peer_info_reset(struct bus1_peer_info *peer_info, bool final)
{
	struct bus1_message *message, *list;

	bus1_handle_flush_all(peer_info, final);

	mutex_lock(&peer_info->lock);
	list = bus1_peer_info_flush(peer_info);
	bus1_pool_flush(&peer_info->pool);
	mutex_unlock(&peer_info->lock);

	while ((message = list)) {
		list = message->transaction.next;
		message->transaction.next = NULL;
		bus1_message_free(message, peer_info);
	}
}

static struct bus1_peer_info *
bus1_peer_info_free(struct bus1_peer_info *peer_info)
{
	if (!peer_info)
		return NULL;

	bus1_peer_info_reset(peer_info, true);

	if (peer_info->seed) {
		mutex_lock(&peer_info->lock);
		bus1_message_deallocate(peer_info->seed, peer_info);
		mutex_unlock(&peer_info->lock);
		peer_info->seed = bus1_message_free(peer_info->seed, peer_info);
	}

	bus1_queue_destroy(&peer_info->queue);
	bus1_pool_destroy(&peer_info->pool);
	bus1_user_quota_destroy(&peer_info->quota);

	peer_info->user = bus1_user_unref(peer_info->user);
	put_pid_ns(peer_info->pid_ns);
	put_cred(peer_info->cred);

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

static struct bus1_peer_info *bus1_peer_info_new(wait_queue_head_t *waitq,
						 size_t pool_size)
{
	struct bus1_peer_info *peer_info;
	int r;

	if (unlikely(pool_size == 0 || !IS_ALIGNED(pool_size, PAGE_SIZE)))
		return ERR_PTR(-EINVAL);

	peer_info = kmalloc(sizeof(*peer_info), GFP_KERNEL);
	if (!peer_info)
		return ERR_PTR(-ENOMEM);

	mutex_init(&peer_info->lock);
	mutex_init(&peer_info->qlock);
	peer_info->cred = get_cred(current_cred());
	peer_info->pid_ns = get_pid_ns(task_active_pid_ns(current));
	peer_info->waitq = waitq;
	peer_info->user = NULL;
	peer_info->seed = NULL;
	bus1_user_quota_init(&peer_info->quota);
	peer_info->pool = BUS1_POOL_NULL;
	bus1_queue_init_for_peer(peer_info);
	peer_info->map_handles_by_id = RB_ROOT;
	peer_info->map_handles_by_node = RB_ROOT;
	seqcount_init(&peer_info->seqcount);
	atomic_set(&peer_info->n_dropped, 0);
	peer_info->handle_ids = 0;

	peer_info->user = bus1_user_ref_by_uid(peer_info->cred->uid);
	if (IS_ERR(peer_info->user)) {
		r = PTR_ERR(peer_info->user);
		peer_info->user = NULL;
		goto error;
	}

	peer_info->n_allocated = pool_size;
	peer_info->n_messages = atomic_read(&peer_info->user->max_messages);
	peer_info->n_handles = atomic_read(&peer_info->user->max_handles);
	peer_info->n_fds = rlimit(RLIMIT_NOFILE);

	r = bus1_pool_create_for_peer(peer_info, pool_size);
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
	struct bus1_peer *peer;

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&peer->waitq);
	bus1_active_init(&peer->active);
	rcu_assign_pointer(peer->info, NULL);

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
	bus1_active_destroy(&peer->active);
	kfree_rcu(peer, rcu);

	return NULL;
}

static void bus1_peer_cleanup(struct bus1_active *active, void *userdata)
{
	struct bus1_peer *peer = container_of(active, struct bus1_peer, active);
	struct bus1_peer_info *peer_info;
	unsigned long flags;

	/* see bus1_peer_connect_new(); we borrow the waitq-lock here */
	spin_lock_irqsave(&peer->waitq.lock, flags);
	peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&peer->waitq.lock));
	rcu_assign_pointer(peer->info, NULL);
	spin_unlock_irqrestore(&peer->waitq.lock, flags);

	if (peer_info) /* might be NULL if never activated */
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
 * bus1_peer_ioctl_init() - initialize peer
 * @peer:		peer to operate on
 * @arg:		ioctl argument
 *
 * This initializes a peer that was created by an open() call, by creating a
 * peer_info object and linking it into the peer.
 *
 * The caller must not hold any active reference to the peer.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl_init(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_cmd_peer_init param;
	struct bus1_peer_info *peer_info;
	unsigned long flags;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_INIT) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) || unlikely(param.pool_size == 0))
		return -EINVAL;

	/*
	 * To connect the peer, we have to set @peer_info on @peer->info *and*
	 * mark the active counter as active. Since this call is fully unlocked
	 * we borrow @peer->waitq.lock to synchronize against parallel
	 * connects *and* disconnects. The critical section just swaps the
	 * pointer and performs a *single* attempt of an atomic cmpxchg (see
	 * bus1_active_activate() for details). Hence, borrowing the waitq-lock
	 * is perfectly fine.
	 */
	peer_info = bus1_peer_info_new(&peer->waitq, param.pool_size);
	if (IS_ERR(peer_info))
		return PTR_ERR(peer_info);

	spin_lock_irqsave(&peer->waitq.lock, flags);
	if (bus1_active_is_deactivated(&peer->active)) {
		r = -ESHUTDOWN;
	} else if (!rcu_access_pointer(peer->info)) {
		rcu_assign_pointer(peer->info, peer_info);
		bus1_active_activate(&peer->active);
		peer_info = NULL; /* mark as consumed */
		r = 0;
	} else {
		r = -EISCONN;
	}
	spin_unlock_irqrestore(&peer->waitq.lock, flags);

	bus1_peer_info_free(peer_info);

	return r;
}

static int bus1_peer_ioctl_query(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_cmd_peer_init __user *uparam = (void __user  *) arg;
	struct bus1_cmd_peer_init param;
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_QUERY) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) || unlikely(param.pool_size))
		return -EINVAL;

	peer_info = bus1_peer_dereference(peer);

	if (put_user(peer_info->pool.size, &uparam->pool_size))
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
	bus1_peer_info_reset(peer_info, false);

	return 0;
}

static int bus1_peer_ioctl_clone(struct bus1_peer *peer,
			  struct file *peer_file,
			  unsigned long arg)
{
	struct bus1_cmd_peer_clone __user *uparam = (void __user *) arg;
	struct bus1_cmd_peer_clone param;
	struct bus1_peer_info *peer_info, *clone_info = NULL;
	struct bus1_peer *clone = NULL;
	struct file *clone_file = NULL;
	int r, fd;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_CLONE) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags) ||
	    unlikely(param.pool_size == 0) ||
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

	clone_info = bus1_peer_info_new(&clone->waitq, param.pool_size);
	if (IS_ERR(clone_info)) {
		r = PTR_ERR(clone_info);
		clone_info = NULL;
		goto error;
	}
	rcu_assign_pointer(clone->info, clone_info);
	bus1_active_activate(&clone->active);
	WARN_ON(!bus1_peer_acquire(clone));

	r = bus1_handle_pair(peer, clone, &param.parent_handle,
			     &param.child_handle);
	if (r < 0)
		goto error;

	fd_install(fd, clone_file); /* consumes file reference */
	bus1_peer_release(clone);

	if (put_user(param.parent_handle, &uparam->parent_handle) ||
	    put_user(param.child_handle, &uparam->child_handle) ||
	    put_user(fd, &uparam->fd))
		return -EFAULT; /* We don't care, keep what we did */

	return 0;

error:
	if (clone_info)
		bus1_peer_release(clone);
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

	r = bus1_handle_destroy_by_id(peer, &id);
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
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	u64 offset;
	int r;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) != sizeof(offset));

	if (get_user(offset, (const u64 __user *)arg))
		return -EFAULT;

	mutex_lock(&peer_info->lock);
	r = bus1_pool_release_user(&peer_info->pool, offset);
	mutex_unlock(&peer_info->lock);

	return r;
}

static int bus1_peer_ioctl_send(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_transaction *transaction = NULL;
	/* Use a stack-allocated buffer for the transaction object if it fits */
	u8 buf[512];
	struct bus1_cmd_send param;
	u64 __user *ptr_dest;
	bool cont;
	size_t i;
	int r;

	lockdep_assert_held(&peer->active);

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SEND) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_SEND_FLAG_CONTINUE |
				     BUS1_SEND_FLAG_SILENT |
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

	cont = param.flags & BUS1_SEND_FLAG_CONTINUE;
	ptr_dest = (u64 __user *)(unsigned long)param.ptr_destinations;

	transaction = bus1_transaction_new_from_user(buf, sizeof(buf), peer,
						     &param);
	if (IS_ERR(transaction))
		return PTR_ERR(transaction);

	if (param.flags & BUS1_SEND_FLAG_SEED) { /* Special-case: set seed */
		if (unlikely((param.flags & (BUS1_SEND_FLAG_SILENT |
					     BUS1_SEND_FLAG_CONTINUE)) ||
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
		if (r < 0 && (r != -ENXIO || !cont))
			goto exit;

	} else { /* Slowpath: any message */
		for (i = 0; i < param.n_destinations; ++i) {
			r = bus1_transaction_instantiate_for_id(transaction,
								ptr_dest + i);
			if (r < 0 && (r != -ENXIO || !cont))
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

static int bus1_peer_dequeue(struct bus1_peer_info *peer_info,
			     struct bus1_cmd_recv *param)
{
	struct bus1_queue_node *node;
	int r;

	mutex_lock(&peer_info->lock);
	mutex_lock(&peer_info->qlock);
	if (param->flags & BUS1_RECV_FLAG_SEED)
		node = peer_info->seed ? &peer_info->seed->qnode : NULL;
	else
		node = bus1_queue_peek(&peer_info->queue);
	if (node) {
		switch (bus1_queue_node_get_type(node)) {
		case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
		case BUS1_QUEUE_NODE_MESSAGE_SILENT: {
			struct bus1_message *message;

			message = bus1_message_from_node(node);
			r = bus1_message_install(message, peer_info);
			if (r < 0) {
				mutex_unlock(&peer_info->qlock);
				mutex_unlock(&peer_info->lock);
				return r;
			}

			if (message == peer_info->seed)
				peer_info->seed = NULL;
			else
				bus1_queue_remove(&peer_info->queue,
						  &message->qnode);

			mutex_unlock(&peer_info->qlock);

			bus1_pool_publish(&peer_info->pool, message->slice);
			bus1_message_deallocate(message, peer_info);

			mutex_unlock(&peer_info->lock);

			param->type = BUS1_MSG_DATA;
			memcpy(&param->data, &message->data,
			       sizeof(param->data));

			bus1_message_free(message, peer_info);
			return 0;
		}
		case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
			bus1_queue_remove(&peer_info->queue, node);
			param->type = BUS1_MSG_NODE_DESTROY;
			param->node_destroy.handle =
				bus1_handle_from_queue(node, peer_info, true);
			mutex_unlock(&peer_info->qlock);
			mutex_unlock(&peer_info->lock);
			return 0;
		case BUS1_QUEUE_NODE_HANDLE_RELEASE:
			bus1_queue_remove(&peer_info->queue, node);
			param->type = BUS1_MSG_NODE_RELEASE;
			param->node_release.handle =
				bus1_handle_from_queue(node, peer_info, true);
			mutex_unlock(&peer_info->qlock);
			mutex_unlock(&peer_info->lock);
			return 0;
		default:
			mutex_unlock(&peer_info->qlock);
			mutex_unlock(&peer_info->lock);

			WARN(1, "Invalid queue-node type");
			return -ENOTRECOVERABLE;
		}
	}
	mutex_unlock(&peer_info->qlock);
	mutex_unlock(&peer_info->lock);

	return 0;
}

static void bus1_peer_peek(struct bus1_peer_info *peer_info,
			   struct bus1_cmd_recv *param)
{
	struct bus1_queue_node *node;
	struct bus1_message *message;

	mutex_lock(&peer_info->lock);
	mutex_lock(&peer_info->qlock);
	if (param->flags & BUS1_RECV_FLAG_SEED)
		node = peer_info->seed ? &peer_info->seed->qnode : NULL;
	else
		node = bus1_queue_peek(&peer_info->queue);
	if (node) {
		switch (bus1_queue_node_get_type(node)) {
		case BUS1_QUEUE_NODE_MESSAGE_NORMAL:
		case BUS1_QUEUE_NODE_MESSAGE_SILENT:
			message = bus1_message_from_node(node);
			bus1_pool_publish(&peer_info->pool, message->slice);
			param->type = BUS1_MSG_DATA;
			memcpy(&param->data, &message->data,
			       sizeof(param->data));
			break;
		case BUS1_QUEUE_NODE_HANDLE_DESTRUCTION:
			param->type = BUS1_MSG_NODE_DESTROY;
			param->node_destroy.handle =
				bus1_handle_from_queue(node, peer_info, false);
			break;
		case BUS1_QUEUE_NODE_HANDLE_RELEASE:
			param->type = BUS1_MSG_NODE_RELEASE;
			param->node_release.handle =
				bus1_handle_from_queue(node, peer_info, false);
			break;
		default:
			WARN(1, "Invalid queue-node type");
			break;
		}
	}
	mutex_unlock(&peer_info->qlock);
	mutex_unlock(&peer_info->lock);
}

static int bus1_peer_ioctl_recv(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
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

	if (param.flags & BUS1_RECV_FLAG_PEEK) {
		bus1_peer_peek(peer_info, &param);
		param.n_dropped = atomic_read(&peer_info->n_dropped);
	} else {
		r = bus1_peer_dequeue(peer_info, &param);
		if (r < 0)
			return r;

		param.n_dropped = atomic_xchg(&peer_info->n_dropped, 0);
	}

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
