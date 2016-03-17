/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include "test.h"

static int client_send(struct bus1_client *client, uint64_t handle, void *data,
		       size_t len)
{
	struct iovec vec = {
		.iov_base = data,
		.iov_len = len,
	};
	struct bus1_cmd_send send = {
		.ptr_destinations = (uint64_t)&handle,
		.n_destinations = 1,
		.ptr_vecs = (uint64_t)&vec,
		.n_vecs = 1,
	};

	return bus1_client_ioctl(client, BUS1_CMD_SEND, &send);
}

static int client_recv(struct bus1_client *client, void **datap, size_t *lenp)
{
	struct bus1_cmd_recv recv = {};
	int r;

	assert(datap);
	assert(lenp);

	r = bus1_client_ioctl(client, BUS1_CMD_RECV, &recv);
	if (r < 0)
		return r;

	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.n_dropped == 0);

	*datap = bus1_client_slice_from_offset(client, recv.data.offset);
	*lenp = recv.data.n_bytes;

	return 0;
}

static int client_slice_release(struct bus1_client *client, void *slice)
{
	return bus1_client_slice_release(client,
				bus1_client_slice_to_offset(client, slice));
}

int test_io(void)
{
	struct bus1_client *c1, *c2;
	uint64_t handle;
	char *payload = "WOOFWOOF";
	char *reply_payload;
	size_t reply_len;
	int r, fd;

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);

	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_clone(c1, &handle, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_new_from_fd(&c2, fd);
	assert(r >= 0);

	r = bus1_client_mmap(c2);
	assert(r >= 0);

	r = client_send(c1, handle, payload, strlen(payload) + 1);
	assert(r >= 0);

	r = client_recv(c2, (void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(c2, reply_payload);
	assert(r >= 0);

	c1 = bus1_client_free(c1);
	c2 = bus1_client_free(c2);

	return TEST_OK;
}
