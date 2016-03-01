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
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "message.h"
#include "peer.h"
#include "pool.h"
#include "queue.h"
#include "transaction.h"
#include "user.h"
#include "util.h"

static void bus1_peer_info_reset(struct bus1_peer_info *peer_info)
{
	struct bus1_queue_node *node, *t;
	struct bus1_message *message;

	mutex_lock(&peer_info->lock);

	rbtree_postorder_for_each_entry_safe(node, t,
					     &peer_info->queue.messages, rb) {
		if (WARN_ON(!bus1_queue_node_is_message(node)))
			continue;

		message = container_of(node, struct bus1_message, qnode);
		RB_CLEAR_NODE(&node->rb);
		if (bus1_queue_node_is_committed(node)) {
			bus1_message_deallocate_locked(message, peer_info);
			bus1_message_free(message);
		}
		/* if uncommitted, the unlink serves as removal marker */
	}
	bus1_queue_post_flush(&peer_info->queue);

	bus1_pool_flush(&peer_info->pool);

	mutex_unlock(&peer_info->lock);
}

static struct bus1_peer_info *
bus1_peer_info_free(struct bus1_peer_info *peer_info)
{
	if (!peer_info)
		return NULL;

	bus1_peer_info_reset(peer_info);

	bus1_queue_destroy(&peer_info->queue);
	bus1_pool_destroy(&peer_info->pool);
	bus1_user_quota_destroy(&peer_info->quota);

	peer_info->user = bus1_user_unref(peer_info->user);

	/*
	 * Make sure the object is freed in a delayed-manner. Some
	 * embedded members (like the queue) must be accessible for an entire
	 * rcu read-side critical section.
	 */
	kfree_rcu(peer_info, rcu);

	return NULL;
}

static struct bus1_peer_info *
bus1_peer_info_new(struct bus1_cmd_connect *param, kuid_t uid)
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
	peer_info->user = NULL;
	bus1_user_quota_init(&peer_info->quota);
	peer_info->pool = BUS1_POOL_NULL;
	bus1_queue_init_for_peer(&peer_info->queue, peer_info);
	peer_info->map_handles_by_id = RB_ROOT;
	peer_info->map_handles_by_node = RB_ROOT;
	seqcount_init(&peer_info->seqcount);
	peer_info->handle_ids = 0;

	peer_info->user = bus1_user_ref_by_uid(uid);
	if (IS_ERR(peer_info->user)) {
		r = PTR_ERR(peer_info->user);
		peer_info->user = NULL;
		goto error;
	}

	r = bus1_pool_create_for_peer(&peer_info->pool, peer_info,
				      param->pool_size);
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
 * Allocate a new peer handle. The handle is *not* activated, nor linked into
 * any context. The caller owns the only pointer to the new peer.
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

/**
 * bus1_peer_teardown() - XXX
 */
int bus1_peer_teardown(struct bus1_peer *peer)
{
	struct bus1_peer_info *peer_info;
	int r = 0;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	/* deactivate and wait for any outstanding operations */
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	if (bus1_active_cleanup(&peer->active, NULL, NULL, NULL)) {
		peer_info = rcu_dereference_protected(peer->info,
					bus1_active_is_drained(&peer->active));
		rcu_assign_pointer(peer->info, NULL);
		if (peer_info)
			bus1_peer_info_free(peer_info);
	} else {
		r = -ESHUTDOWN;
	}

	up_write(&peer->rwlock);

	return r;
}

static int bus1_peer_connect_new(struct bus1_peer *peer,
				 kuid_t uid,
				 struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&peer->rwlock);

	if (!bus1_active_is_new(&peer->active))
		return -EISCONN;
	if (WARN_ON(rcu_access_pointer(peer->info)))
		return -EISCONN;
	if (param->flags & BUS1_CONNECT_FLAG_MONITOR)
		return -ENOTSUPP; /* XXX: not yet implemented */

	peer_info = bus1_peer_info_new(param, uid);
	if (IS_ERR(peer_info))
		return PTR_ERR(peer_info);

	rcu_assign_pointer(peer->info, peer_info);
	bus1_active_activate(&peer->active);

	return 0;
}

static int bus1_peer_connect_reset(struct bus1_peer *peer,
				   struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;

	/*
	 * XXX: reset?
	 */

	lockdep_assert_held(&peer->rwlock);

	if (bus1_active_is_new(&peer->active))
		return -ENOTCONN;
	if (param->pool_size != 0 || param->size > sizeof(*param))
		return -EINVAL;

	peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&peer->rwlock));
	if (WARN_ON(!peer_info))
		return -ESHUTDOWN;

	/* provide information for caller */
	param->pool_size = peer_info->pool.size;

	bus1_peer_info_reset(peer_info);

	return 0;
}

static int bus1_peer_connect_query(struct bus1_peer *peer,
				   struct bus1_cmd_connect *param)
{
	struct bus1_peer_info *peer_info;

	lockdep_assert_held(&peer->rwlock);

	if (bus1_active_is_new(&peer->active))
		return -ENOTCONN;

	peer_info = rcu_dereference_protected(peer->info,
					lockdep_is_held(&peer->rwlock));
	if (WARN_ON(!peer_info))
		return -ESHUTDOWN;

	param->pool_size = peer_info->pool.size;

	return 0;
}

static int bus1_peer_ioctl_connect(struct bus1_peer *peer,
				   const struct file *file,
				   unsigned long arg)
{
	struct bus1_cmd_connect __user *uparam = (void __user *)arg;
	struct bus1_cmd_connect *param;
	int r;

	param = bus1_import_dynamic_ioctl(arg, sizeof(*param));
	if (IS_ERR(param))
		return PTR_ERR(param);

	/* check for validity of all flags */
	if (param->flags & ~(BUS1_CONNECT_FLAG_CLIENT |
			     BUS1_CONNECT_FLAG_MONITOR |
			     BUS1_CONNECT_FLAG_QUERY |
			     BUS1_CONNECT_FLAG_RESET))
		return -EINVAL;
	/* only one mode can be specified */
	if (!!(param->flags & BUS1_CONNECT_FLAG_CLIENT) +
	    !!(param->flags & BUS1_CONNECT_FLAG_MONITOR) +
	    !!(param->flags & BUS1_CONNECT_FLAG_RESET) > 1)
		return -EINVAL;

	/* lock against parallel CONNECT/DISCONNECT */
	down_write(&peer->rwlock);

	if (bus1_active_is_deactivated(&peer->active)) {
		/* all fails, if the peer was already disconnected */
		r = -ESHUTDOWN;
	} else if (param->flags & (BUS1_CONNECT_FLAG_CLIENT |
				   BUS1_CONNECT_FLAG_MONITOR)) {
		/* fresh connect of a new peer */
		r = bus1_peer_connect_new(peer, file->f_cred->uid, param);
	} else if (param->flags & BUS1_CONNECT_FLAG_RESET) {
		/* reset of the peer requested */
		r = bus1_peer_connect_reset(peer, param);
	} else if (param->flags & BUS1_CONNECT_FLAG_QUERY) {
		/* fallback: no special operation specified, just query */
		r = bus1_peer_connect_query(peer, param);
	} else {
		r = -EINVAL; /* no mode specified */
	}

	up_write(&peer->rwlock);

	/*
	 * QUERY can be combined with any CONNECT operation. On success, it
	 * causes the peer information to be copied back to user-space.
	 * All handlers above must provide that information in @param for this
	 * to copy it back.
	 */
	if (r >= 0 && (param->flags & BUS1_CONNECT_FLAG_QUERY)) {
		if (put_user(param->pool_size, &uparam->pool_size))
			r = -EFAULT; /* Don't care.. keep what we did so far */
	}

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

static int bus1_peer_ioctl_send(struct bus1_peer *peer, unsigned long arg)
{
	struct bus1_peer_info *peer_info = bus1_peer_dereference(peer);
	struct bus1_transaction *transaction = NULL;
	/* Use a stack-allocated buffer for the transaction object if it fits */
	u8 buf[512];
	const u64 __user *ptr_dest;
	struct bus1_cmd_send param;
	u64 destination;
	size_t i;
	int r;

	lockdep_assert_held(&peer->active);

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
	    unlikely(param.ptr_ids !=
		     (u64)(unsigned long)param.ptr_ids) ||
	    unlikely(param.ptr_fds !=
		     (u64)(unsigned long)param.ptr_fds))
		return -EFAULT;

	transaction = bus1_transaction_new_from_user(peer_info, &param,
						     buf, sizeof(buf),
						     bus1_in_compat_syscall());
	if (IS_ERR(transaction))
		return PTR_ERR(transaction);

	ptr_dest = (const u64 __user *)(unsigned long)param.ptr_destinations;
	if (param.n_destinations == 1) { /* Fastpath: unicast */
		if (get_user(destination, ptr_dest)) {
			r = -EFAULT; /* faults are always fatal */
			goto exit;
		}

		r = bus1_transaction_commit_for_id(transaction,
						   peer->info->user,
						   destination,
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
							peer->info->user,
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
	struct bus1_queue_node *node;
	struct bus1_message *message;
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
	    unlikely(param.msg_ids != 0) ||
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
	node = bus1_queue_peek_rcu(&peer_info->queue);
	if (node) {
		WARN_ON(!bus1_queue_node_is_message(node));
		message = bus1_message_from_node(node);
		wanted_fds = message->n_files;
	}
	rcu_read_unlock();
	if (!node)
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
		node = bus1_queue_peek(&peer_info->queue);
		if (node) {
			message = bus1_message_from_node(node);
			bus1_pool_publish(&peer_info->pool, message->slice,
					  &param.msg_offset, &param.msg_size);
			param.msg_fds = message->n_files;
		}
		mutex_unlock(&peer_info->lock);

		if (!node)
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
		node = bus1_queue_peek(&peer_info->queue);
		message = node ? bus1_message_from_node(node) : NULL;
		if (!node) {
			/* nothing to do, caught below */
		} else if (message->n_files > n_fds) {
			/* re-allocate FD array and retry */
			wanted_fds = message->n_files;
		} else {
			bus1_queue_remove(&peer_info->queue, node);
			bus1_pool_publish(&peer_info->pool, message->slice,
					  &param.msg_offset, &param.msg_size);
			param.msg_fds = message->n_files;

			/*
			 * Fastpath: If no FD is transmitted, we can avoid the
			 *           second lock below. Directly release the
			 *           slice.
			 */
			if (message->n_files == 0)
				bus1_message_deallocate_locked(message,
							       peer_info);
		}
		mutex_unlock(&peer_info->lock);
	} while (wanted_fds > n_fds);

	if (!node) {
		r = -EAGAIN;
		goto exit;
	}

	while (n_fds > message->n_files)
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

		r = bus1_pool_write_kvec(&peer_info->pool, message->slice,
					 message->slice->size - vec.iov_len,
					 &vec, 1, vec.iov_len);

		mutex_lock(&peer_info->lock);
		bus1_message_deallocate_locked(message, peer_info);
		mutex_unlock(&peer_info->lock);

		/* on success, install FDs; on error, see fput() in `exit:' */
		if (r >= 0) {
			for ( ; n_fds > 0; --n_fds)
				fd_install(fds[n_fds - 1],
					   get_file(message->files[n_fds - 1]));
		} else {
			/* XXX: convey error, just like in transactions */
		}
	} else {
		/* slice is already released, nothing to do */
		r = 0;
	}

	bus1_message_free(message);

exit:
	if (r >= 0) {
		if (put_user(param.msg_offset, &uparam->msg_offset) ||
		    put_user(param.msg_size, &uparam->msg_size) ||
		    put_user(param.msg_ids, &uparam->msg_ids) ||
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
 * @file:		file this ioctl is called on
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on the passed peer. The caller must
 * not hold an active reference to the peer.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_peer_ioctl(struct bus1_peer *peer,
		    const struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	int r = -ENOTTY;

	switch (cmd) {
	case BUS1_CMD_CONNECT:
		r = bus1_peer_ioctl_connect(peer, file, arg);
		break;

	case BUS1_CMD_DISCONNECT:
		/* no arguments allowed, it behaves like the last close() */
		if (arg != 0)
			return -EINVAL;

		return bus1_peer_teardown(peer);

	case BUS1_CMD_SLICE_RELEASE:
	case BUS1_CMD_SEND:
	case BUS1_CMD_RECV:
		down_read(&peer->rwlock);
		if (!bus1_peer_acquire(peer)) {
			r = -ESHUTDOWN;
		} else {
			if (cmd == BUS1_CMD_SLICE_RELEASE)
				r = bus1_peer_ioctl_slice_release(peer, arg);
			else if (cmd == BUS1_CMD_SEND)
				r = bus1_peer_ioctl_send(peer, arg);
			else if (cmd == BUS1_CMD_RECV)
				r = bus1_peer_ioctl_recv(peer, arg);
			bus1_peer_release(peer);
		}
		up_read(&peer->rwlock);
		break;
	}

	return r;
}
