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

static int client_send(struct bus1_client *client, uint64_t *handles,
		       size_t n_handles, void *data, size_t len)
{
	struct iovec vec = {
		.iov_base = data,
		.iov_len = len,
	};
	struct bus1_cmd_send send = {
		.flags = n_handles > 1 ? BUS1_SEND_FLAG_CONTINUE : 0,
		.ptr_destinations = (uint64_t)handles,
		.n_destinations = (uint64_t)n_handles,
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
	struct bus1_client *sender, *receiver1, *receiver2;
	uint64_t handles[2];
	char *payload = "WOOFWOOF";
	char *reply_payload;
	size_t reply_len;
	int r, fd;

	/* create parent */
	r = bus1_client_new_from_path(&sender, test_path);
	assert(r >= 0);

	r = bus1_client_init(sender, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	/* create first child */
	r = bus1_client_clone(sender, handles, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_new_from_fd(&receiver1, fd);
	assert(r >= 0);

	r = bus1_client_mmap(receiver1);
	assert(r >= 0);

	/* unicast */
	r = client_send(sender, handles, 1, payload, strlen(payload) + 1);
	assert(r >= 0);

	r = client_recv(receiver1, (void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(receiver1, reply_payload);
	assert(r >= 0);

	/* create second child */
	r = bus1_client_clone(sender, handles + 1, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_new_from_fd(&receiver2, fd);
	assert(r >= 0);

	r = bus1_client_mmap(receiver2);
	assert(r >= 0);

	/* multicast */
	r = client_send(sender, handles, 2, payload, strlen(payload) + 1);
	fprintf(stderr, "send failed: %s\n", strerror(-r));
	assert(r >= 0);

	r = client_recv(receiver1, (void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(receiver1, reply_payload);
	assert(r >= 0);

	r = client_recv(receiver2, (void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(receiver2, reply_payload);
	assert(r >= 0);

	/* cleanup */
	sender = bus1_client_free(sender);
	receiver1 = bus1_client_free(receiver1);
	receiver2 = bus1_client_free(receiver2);

	return TEST_OK;
}
