/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "handle.h"
#include "message.h"
#include "peer.h"
#include "security.h"
#include "tx.h"
#include "user.h"
#include "util.h"
#include "util/flist.h"
#include "util/pool.h"
#include "util/queue.h"

static size_t bus1_factory_size(struct bus1_cmd_send *param)
{
	/* make sure @size cannot overflow */
	BUILD_BUG_ON(UIO_MAXIOV > U16_MAX);
	BUILD_BUG_ON(BUS1_FD_MAX > U16_MAX);

	/* make sure we do not violate alignment rules */
	BUILD_BUG_ON(__alignof(struct bus1_flist) < __alignof(struct iovec));
	BUILD_BUG_ON(__alignof(struct iovec) < __alignof(struct file *));

	return sizeof(struct bus1_factory) +
	       bus1_flist_inline_size(param->n_handles) +
	       param->n_vecs * sizeof(struct iovec) +
	       param->n_fds * sizeof(struct file *);
}

/**
 * bus1_factory_new() - create new message factory
 * @peer:			peer to operate as
 * @param:			factory parameters
 * @stack:			optional stack for factory, or NULL
 * @n_stack:			size of space at @stack
 *
 * This allocates a new message factory. It imports data from @param and
 * prepares the factory for a transaction. From this factory, messages can be
 * instantiated. This is used both for unicasts and multicasts.
 *
 * If @stack is given, this tries to place the factory on the specified stack
 * space. The caller must guarantee that the factory does not outlive the stack
 * frame. If this is not wanted, pass 0 as @n_stack.
 * In either case, if the stack frame is too small, this will allocate the
 * factory on the heap.
 *
 * Return: Pointer to factory, or ERR_PTR on failure.
 */
struct bus1_factory *bus1_factory_new(struct bus1_peer *peer,
				      struct bus1_cmd_send *param,
				      void *stack,
				      size_t n_stack)
{
	const struct iovec __user *ptr_vecs;
	const u64 __user *ptr_handles;
	const int __user *ptr_fds;
	struct bus1_factory *f;
	struct bus1_flist *e;
	struct file *file;
	size_t i, size;
	bool is_new;
	int r, fd;
	u64 id;

	lockdep_assert_held(&peer->local.lock);

	size = bus1_factory_size(param);
	if (unlikely(size > n_stack)) {
		f = kmalloc(size, GFP_TEMPORARY);
		if (!f)
			return ERR_PTR(-ENOMEM);

		f->on_stack = false;
	} else {
		f = stack;
		f->on_stack = true;
	}

	/* set to default first, so the destructor can be called anytime */
	f->peer = peer;
	f->param = param;

	f->length_vecs = 0;
	f->n_vecs = param->n_vecs;
	f->n_handles = 0;
	f->n_handles_charge = 0;
	f->n_files = 0;
	f->vecs = (void *)(f + 1) + bus1_flist_inline_size(param->n_handles);
	f->files = (void *)(f->vecs + param->n_vecs);
	bus1_flist_init(f->handles, f->param->n_handles);

	/* import vecs */
	ptr_vecs = (const struct iovec __user *)(unsigned long)param->ptr_vecs;
	r = bus1_import_vecs(f->vecs, &f->length_vecs, ptr_vecs, f->n_vecs);
	if (r < 0)
		goto error;

	/* import handles */
	r = bus1_flist_populate(f->handles, f->param->n_handles, GFP_TEMPORARY);
	if (r < 0)
		goto error;

	ptr_handles = (const u64 __user *)(unsigned long)param->ptr_handles;
	for (i = 0, e = f->handles;
	     i < f->param->n_handles;
	     e = bus1_flist_next(e, &i)) {
		if (get_user(id, ptr_handles + f->n_handles)) {
			r = -EFAULT;
			goto error;
		}

		e->ptr = bus1_handle_import(peer, id, &is_new);
		if (IS_ERR(e->ptr)) {
			r = PTR_ERR(e->ptr);
			goto error;
		}

		++f->n_handles;
		if (is_new)
			++f->n_handles_charge;
	}

	/* import files */
	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	while (f->n_files < param->n_fds) {
		if (get_user(fd, ptr_fds + f->n_files)) {
			r = -EFAULT;
			goto error;
		}

		file = bus1_import_fd(fd);
		if (IS_ERR(file)) {
			r = PTR_ERR(file);
			goto error;
		}

		f->files[f->n_files++] = file;
	}

	return f;

error:
	bus1_factory_free(f);
	return ERR_PTR(r);
}

/**
 * bus1_factory_free() - destroy message factory
 * @f:				factory to operate on, or NULL
 *
 * This destroys the message factory @f, previously created via
 * bus1_factory_new(). All pinned resources are freed. Messages created via the
 * factory are unaffected.
 *
 * If @f is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_factory *bus1_factory_free(struct bus1_factory *f)
{
	struct bus1_flist *e;
	size_t i;

	if (f) {
		lockdep_assert_held(&f->peer->local.lock);

		for (i = 0; i < f->n_files; ++i)
			fput(f->files[i]);

		/* Iterate and forget imported handles (f->n_handles)... */
		for (i = 0, e = f->handles;
		     i < f->n_handles;
		     e = bus1_flist_next(e, &i)) {
			bus1_handle_forget(e->ptr);
			bus1_handle_unref(e->ptr);
		}
		/* ...but free total space (f->param->n_handles). */
		bus1_flist_deinit(f->handles, f->param->n_handles);

		if (!f->on_stack)
			kfree(f);
	}

	return NULL;
}

/**
 * bus1_factory_seal() - charge and commit local resources
 * @f:				factory to use
 *
 * The factory needs to pin and possibly create local peer resources. This
 * commits those resources. You should call this after you instantiated all
 * messages, since you cannot undo it easily.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_factory_seal(struct bus1_factory *f)
{
	struct bus1_handle *h;
	struct bus1_flist *e;
	size_t i;
	int r;

	lockdep_assert_held(&f->peer->local.lock);

	r = bus1_user_charge(&f->peer->user->limits.n_handles,
			     &f->peer->data.limits.n_handles,
			     f->n_handles_charge);
	if (r < 0)
		return r;

	for (i = 0, e = f->handles;
	     i < f->n_handles;
	     e = bus1_flist_next(e, &i)) {
		h = e->ptr;
		if (bus1_handle_is_public(h))
			continue;

		--f->n_handles_charge;
		WARN_ON(h != bus1_handle_acquire(h, false));
		WARN_ON(atomic_inc_return(&h->n_user) != 1);
	}

	return 0;
}

/**
 * bus1_factory_instantiate() - instantiate a message from a factory
 * @f:				factory to use
 * @handle:			destination handle
 * @peer:			destination peer
 *
 * This instantiates a new message targeted at @handle, based on the plans in
 * the message factory @f.
 *
 * The newly created message is not linked into any contexts, but is available
 * for free use to the caller.
 *
 * Return: Pointer to new message, or ERR_PTR on failure.
 */
struct bus1_message *bus1_factory_instantiate(struct bus1_factory *f,
					      struct bus1_handle *handle,
					      struct bus1_peer *peer)
{
	struct bus1_flist *src_e, *dst_e;
	struct bus1_message *m;
	size_t size, i, j;
	int r;

	lockdep_assert_held(&f->peer->local.lock);

	r = bus1_user_charge(&peer->user->limits.n_slices,
			     &peer->data.limits.n_slices, 1);
	if (r < 0)
		return ERR_PTR(r);

	r = bus1_user_charge(&peer->user->limits.n_handles,
			     &peer->data.limits.n_handles, f->n_handles);
	if (r < 0) {
		bus1_user_discharge(&peer->user->limits.n_slices,
				    &peer->data.limits.n_slices, 1);
		return ERR_PTR(r);
	}

	size = sizeof(*m) + bus1_flist_inline_size(f->n_handles) +
	       f->n_files * sizeof(struct file *);
	m = kmalloc(size, GFP_KERNEL);
	if (!m) {
		bus1_user_discharge(&peer->user->limits.n_handles,
				    &peer->data.limits.n_handles, f->n_handles);
		bus1_user_discharge(&peer->user->limits.n_slices,
				    &peer->data.limits.n_slices, 1);
		return ERR_PTR(-ENOMEM);
	}

	/* set to default first, so the destructor can be called anytime */
	kref_init(&m->ref);
	bus1_queue_node_init(&m->qnode, BUS1_MSG_DATA);
	m->qnode.owner = peer;
	m->dst = bus1_handle_ref(handle);
	m->user = bus1_user_ref(f->peer->user);

	m->flags = 0;

	m->n_bytes = f->length_vecs;
	m->n_handles = 0;
	m->n_handles_charge = f->n_handles;
	m->n_files = 0;
	bus1_pool_slice_init(&m->slice);
	m->files = (void *)(m + 1) + bus1_flist_inline_size(f->n_handles);
	bus1_flist_init(m->handles, f->n_handles);

	/* allocate pool slice */
	size = max_t(size_t, 8,
			     ALIGN(m->n_bytes, 8) +
			     ALIGN(f->n_handles * sizeof(u64), 8) +
			     ALIGN(f->n_files * sizeof(int), 8));
	mutex_lock(&peer->data.lock);
	r = bus1_pool_alloc(&peer->data.pool, &m->slice, size);
	mutex_unlock(&peer->data.lock);
	if (r < 0)
		goto error;

	/* import blob */
	r = bus1_pool_write_iovec(&peer->data.pool, &m->slice, 0, f->vecs,
				  f->n_vecs, f->length_vecs);
	if (r < 0)
		goto error;

	/* import handles */
	r = bus1_flist_populate(m->handles, f->n_handles, GFP_KERNEL);
	if (r < 0)
		goto error;

	r = 0;
	m->n_handles = f->n_handles;
	i = 0;
	j = 0;
	src_e = f->handles;
	dst_e = m->handles;
	while (i < f->n_handles) {
		WARN_ON(i != j);

		dst_e->ptr = bus1_handle_ref_by_other(peer, src_e->ptr);
		if (!dst_e->ptr) {
			dst_e->ptr = bus1_handle_new_remote(peer, src_e->ptr);
			if (IS_ERR(dst_e->ptr) && r >= 0) {
				/*
				 * Continue on error until we imported all
				 * handles. Otherwise, trailing entries in the
				 * array will be stale, and the destructor
				 * cannot tell which.
				 */
				r = PTR_ERR(dst_e->ptr);
			}
		}

		src_e = bus1_flist_next(src_e, &i);
		dst_e = bus1_flist_next(dst_e, &j);
	}
	if (r < 0)
		goto error;

	/* import files */
	while (m->n_files < f->n_files) {
		r = security_bus1_transfer_file(f->peer, peer,
						f->files[m->n_files]);
		if (r < 0)
			goto error;

		m->files[m->n_files] = get_file(f->files[m->n_files]);
		++m->n_files;
	}

	return m;

error:
	bus1_message_unref(m);
	return ERR_PTR(r);
}

/**
 * bus1_message_deinit() - release file descriptors and handles of message
 * @m:		message to operate on
 *
 * This frees the fds and handles pinned by the message @m.
 */
void bus1_message_deinit(struct bus1_message *m)
{
	struct bus1_peer *peer = m->qnode.owner;
	struct bus1_flist *e;
	size_t i;

	WARN_ON(!peer);
	lockdep_assert_held(&peer->active);

	for (i = 0; i < m->n_files; ++i)
		fput(m->files[i]);
	m->n_files = 0;

	for (i = 0, e = m->handles;
	     i < m->n_handles;
	     e = bus1_flist_next(e, &i)) {
		if (!IS_ERR_OR_NULL(e->ptr)) {
			if (m->qnode.group)
				bus1_handle_release(e->ptr, true);
			bus1_handle_unref(e->ptr);
		}
	}
	bus1_user_discharge(&peer->user->limits.n_handles,
			    &peer->data.limits.n_handles, m->n_handles_charge);
	bus1_flist_deinit(m->handles, m->n_handles);
	m->n_handles = 0;

	m->dst = bus1_handle_unref(m->dst);
	bus1_queue_node_deinit(&m->qnode);
}

/**
 * bus1_message_free() - destroy message
 * @k:			kref belonging to a message
 *
 * This frees the message belonging to the reference counter @k. It is supposed
 * to be used with kref_put(). See bus1_message_unref(). Like all queue nodes,
 * the memory deallocation is rcu-delayed.
 */
void bus1_message_free(struct kref *k)
{
	struct bus1_message *m = container_of(k, struct bus1_message, ref);
	struct bus1_peer *peer = m->qnode.owner;

	bus1_message_deinit(m);

	mutex_lock(&peer->data.lock);
	bus1_pool_dealloc(&peer->data.pool, &m->slice);
	mutex_unlock(&peer->data.lock);
	bus1_user_discharge(&peer->user->limits.n_slices,
			    &peer->data.limits.n_slices, 1);

	bus1_user_unref(m->user);

	kfree_rcu(m, qnode.rcu);
}

/**
 * bus1_message_stage() - stage message
 * @m:				message to operate on
 * @tx:				transaction to stage on
 *
 * This acquires all resources of the message @m and then stages the message on
 * @tx. Like all stage operations, this cannot be undone. Hence, you must make
 * sure you can continue to commit the transaction without erroring-out in
 * between.
 *
 * This consumes the caller's reference on @m, plus the active reference on the
 * destination peer.
 */
void bus1_message_stage(struct bus1_message *m, struct bus1_tx *tx)
{
	struct bus1_peer *peer = m->qnode.owner;
	struct bus1_flist *e;
	size_t i;

	WARN_ON(!peer);
	lockdep_assert_held(&peer->active);

	for (i = 0, e = m->handles;
	     i < m->n_handles;
	     e = bus1_flist_next(e, &i))
		e->ptr = bus1_handle_acquire(e->ptr, true);

	/* this consumes an active reference on m->qnode.owner */
	bus1_tx_stage_sync(tx, &m->qnode);
}

/**
 * bus1_message_install() - install message payload into target process
 * @m:				message to operate on
 * @inst_fds:			whether to install FDs
 *
 * This installs the payload FDs and handles of @message into the receiving
 * peer and the calling process. Handles are always installed, FDs are only
 * installed if explicitly requested via @inst_fds.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_message_install(struct bus1_message *m, bool inst_fds)
{
	size_t i, j, n, size, offset, n_handles = 0, n_fds = 0;
	struct bus1_peer *peer = m->qnode.owner;
	struct bus1_handle *h;
	struct bus1_flist *e;
	struct kvec vec;
	u64 ts, *handles;
	u8 stack[512];
	void *buffer = stack;
	int r, *fds;

	WARN_ON(!peer);
	lockdep_assert_held(&peer->local.lock);

	size = max(m->n_files, min_t(size_t, m->n_handles, BUS1_FLIST_BATCH));
	size *= max(sizeof(*fds), sizeof(*handles));
	if (unlikely(size > sizeof(stack))) {
		buffer = kmalloc(size, GFP_TEMPORARY);
		if (!buffer)
			return -ENOMEM;
	}

	if (m->n_handles > 0) {
		handles = buffer;
		ts = bus1_queue_node_get_timestamp(&m->qnode);
		offset = ALIGN(m->n_bytes, 8);

		i = 0;
		while ((n = bus1_flist_walk(m->handles, m->n_handles,
					    &e, &i)) > 0) {
			WARN_ON(i > m->n_handles);
			WARN_ON(i > BUS1_FLIST_BATCH);

			for (j = 0; j < n; ++j) {
				h = e[j].ptr;
				if (h && bus1_handle_is_live_at(h, ts)) {
					handles[j] = bus1_handle_identify(h);
					++n_handles;
				} else {
					bus1_handle_release(h, true);
					e[j].ptr = bus1_handle_unref(h);
					handles[j] = BUS1_HANDLE_INVALID;
				}
			}

			vec.iov_base = buffer;
			vec.iov_len = n * sizeof(u64);

			r = bus1_pool_write_kvec(&peer->data.pool, &m->slice,
						 offset, &vec, 1, vec.iov_len);
			if (r < 0)
				goto exit;

			offset += n * sizeof(u64);
		}
	}

	if (inst_fds && m->n_files > 0) {
		fds = buffer;

		for ( ; n_fds < m->n_files; ++n_fds) {
			r = get_unused_fd_flags(O_CLOEXEC);
			if (r < 0)
				goto exit;

			fds[n_fds] = r;
		}

		vec.iov_base = fds;
		vec.iov_len = n_fds * sizeof(int);
		offset = ALIGN(m->n_bytes, 8) +
			 ALIGN(m->n_handles * sizeof(u64), 8);

		r = bus1_pool_write_kvec(&peer->data.pool, &m->slice, offset,
					 &vec, 1, vec.iov_len);
		if (r < 0)
			goto exit;
	}

	/* charge resources */
	WARN_ON(n_handles < m->n_handles_charge);
	m->n_handles_charge -= n_handles;

	/* publish pool slice */
	bus1_message_ref(m);
	bus1_pool_publish(&m->slice);

	/* commit handles */
	for (i = 0, e = m->handles;
	     i < m->n_handles;
	     e = bus1_flist_next(e, &i)) {
		h = e->ptr;
		if (!IS_ERR_OR_NULL(h)) {
			WARN_ON(h != bus1_handle_acquire(h, true));
			WARN_ON(atomic_inc_return(&h->n_user) < 1);
		}
	}

	/* commit FDs */
	while (n_fds > 0) {
		--n_fds;
		fd_install(fds[n_fds], get_file(m->files[n_fds]));
	}

	r = 0;

exit:
	while (n_fds-- > 0)
		put_unused_fd(fds[n_fds]);
	if (buffer != stack)
		kfree(buffer);
	return r;
}
