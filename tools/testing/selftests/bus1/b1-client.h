#ifndef __B1_CLIENT_H
#define __B1_CLIENT_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Bus1 Client API
 *
 * XXX
 */

#include <inttypes.h>
#include <linux/bus1.h>
#include <sys/uio.h>

struct b1_client;

int b1_client_new_from_fd(struct b1_client **out, int fd);
int b1_client_new_from_path(struct b1_client **out, const char *path);
struct b1_client *b1_client_free(struct b1_client *client);

int b1_client_connect(struct b1_client *client, uint64_t flags,
		      size_t pool_size);
int b1_client_disconnect(struct b1_client *client);

int b1_client_send(struct b1_client *client,
		   uint64_t flags,
		   const uint64_t *dests,
		   size_t n_dests,
		   const struct iovec *vecs,
		   size_t n_vecs);
int b1_client_recv(struct b1_client *client,
		   uint64_t flags,
		   const void **slicep,
		   size_t *sizep);
int b1_client_slice_release(struct b1_client *client, const void *slice);

#endif /* __B1_CLIENT_H */
