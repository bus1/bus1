#ifndef __BUS1_MESSAGE_H
#define __BUS1_MESSAGE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Messages
 *
 * XXX
 */

#include <linux/kernel.h>
#include <linux/kref.h>
#include "util/flist.h"
#include "util/pool.h"
#include "util/queue.h"

struct bus1_cmd_send;
struct bus1_handle;
struct bus1_peer;
struct bus1_tx;
struct bus1_user;
struct file;
struct iovec;

/**
 * struct bus1_factory - message factory
 * @peer:			sending peer
 * @param:			factory parameters
 * @on_stack:			whether object lives on stack
 * @length_vecs:		total length of data in vectors
 * @n_vecs:			number of vectors
 * @n_handles:			number of handles
 * @n_handles_charge:		number of handles to charge on commit
 * @n_files:			number of files
 * @vecs:			vector array
 * @files:			file array
 * @handles:			handle array
 */
struct bus1_factory {
	struct bus1_peer *peer;
	struct bus1_cmd_send *param;

	bool on_stack : 1;

	size_t length_vecs;
	size_t n_vecs;
	size_t n_handles;
	size_t n_handles_charge;
	size_t n_files;
	struct iovec *vecs;
	struct file **files;

	struct bus1_flist handles[];
};

/**
 * struct bus1_message - data messages
 * @ref:			reference counter
 * @qnode:			embedded queue node
 * @dst:			destination handle
 * @user:			sending user
 * @flags:			message flags
 * @n_bytes:			number of user-bytes transmitted
 * @n_handles:			number of handles transmitted
 * @n_handles_charge:		number of handle charges
 * @n_files:			number of files transmitted
 * @slice:			actual message data
 * @files:			passed file descriptors
 * @handles:			passed handles
 */
struct bus1_message {
	struct kref ref;
	struct bus1_queue_node qnode;
	struct bus1_handle *dst;
	struct bus1_user *user;

	u64 flags;

	size_t n_bytes;
	size_t n_handles;
	size_t n_handles_charge;
	size_t n_files;
	struct bus1_pool_slice slice;
	struct file **files;

	struct bus1_flist handles[];
};

struct bus1_factory *bus1_factory_new(struct bus1_peer *peer,
				      struct bus1_cmd_send *param,
				      void *stack,
				      size_t n_stack);
struct bus1_factory *bus1_factory_free(struct bus1_factory *f);
int bus1_factory_seal(struct bus1_factory *f);
struct bus1_message *bus1_factory_instantiate(struct bus1_factory *f,
					      struct bus1_handle *handle,
					      struct bus1_peer *peer);

void bus1_message_deinit(struct bus1_message *m);
void bus1_message_free(struct kref *k);
void bus1_message_stage(struct bus1_message *m, struct bus1_tx *tx);
int bus1_message_install(struct bus1_message *m, bool inst_fds);

/**
 * bus1_message_ref() - acquire object reference
 * @m:			message to operate on, or NULL
 *
 * This acquires a single reference to @m. The caller must already hold a
 * reference when calling this.
 *
 * If @m is NULL, this is a no-op.
 *
 * Return: @m is returned.
 */
static inline struct bus1_message *bus1_message_ref(struct bus1_message *m)
{
	if (m)
		kref_get(&m->ref);
	return m;
}

/**
 * bus1_message_unref() - release object reference
 * @m:			message to operate on, or NULL
 *
 * This releases a single object reference to @m. If the reference counter
 * drops to 0, the message is destroyed.
 *
 * If @m is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_message *bus1_message_unref(struct bus1_message *m)
{
	if (m)
		kref_put(&m->ref, bus1_message_free);
	return NULL;
}

#endif /* __BUS1_MESSAGE_H */
