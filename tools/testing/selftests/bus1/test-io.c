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
#include <time.h>
#include "test.h"

static int client_send(struct bus1_client *client, uint64_t *handles,
		       size_t n_handles, void *data, size_t len)
{
	struct iovec vec = {
		.iov_base = data,
		.iov_len = len,
	};

	return bus1_client_send(client, handles, n_handles, &vec, 1, NULL, 0,
				NULL, 0);
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

static void test_basic(void)
{
	struct bus1_client *sender, *receiver1, *receiver2;
	uint64_t node, handles[2], aux;
	struct bus1_cmd_recv recv;
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
	r = bus1_client_clone(sender, &node, handles, &fd,
			      BUS1_CLIENT_POOL_SIZE);
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
	r = bus1_client_clone(sender, &node, handles + 1, &fd,
			      BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_new_from_fd(&receiver2, fd);
	assert(r >= 0);

	r = bus1_client_mmap(receiver2);
	assert(r >= 0);

	/* multicast */
	r = client_send(sender, handles, 2, payload, strlen(payload) + 1);
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

	/* allocate and send node as auxiliary data */
	aux = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = bus1_client_send(sender, handles, 1, NULL, 0, &aux, 1, NULL, 0);
	assert(r >= 0);
	assert(!(aux & BUS1_NODE_FLAG_ALLOCATE));
	assert(aux & BUS1_NODE_FLAG_MANAGED);

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_ioctl(receiver1, BUS1_CMD_RECV, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.n_dropped == 0);
	assert(recv.data.n_bytes == 0);
	assert(recv.data.n_fds == 0);
	assert(recv.data.n_handles == 1);
	r = bus1_client_slice_release(receiver1, recv.data.offset);
	assert(r >= 0);

	/* cleanup */
	sender = bus1_client_free(sender);
	receiver1 = bus1_client_free(receiver1);
	receiver2 = bus1_client_free(receiver2);
}

static inline uint64_t nsec_from_clock(clockid_t clock)
{
	struct timespec ts;
	int r;

	r = clock_gettime(clock, &ts);
	assert(r >= 0);
	return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static uint64_t test_iterate(unsigned int iterations,
			     unsigned int n_destinations,
			     size_t n_bytes)
{
	struct bus1_client *sender, *receivers[n_destinations];
	uint64_t handles[n_destinations];
	char payload[n_bytes];
	char *reply_payload;
	size_t reply_len;
	unsigned int j, i;
	uint64_t node, time_start, time_end;
	int r, fd;

	/* create parent */
	r = bus1_client_new_from_path(&sender, test_path);
	assert(r >= 0);

	r = bus1_client_init(sender, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	/* create children */
	for (i = 0; i < n_destinations; i++) {
		r = bus1_client_clone(sender, &node, handles + i,
				      &fd, BUS1_CLIENT_POOL_SIZE);
		assert(r >= 0);

		r = bus1_client_new_from_fd(receivers + i, fd);
		assert(r >= 0);

		r = bus1_client_mmap(receivers[i]);
		assert(r >= 0);
	}

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (j = 0; j < iterations; j++) {
		/* send */
		r = client_send(sender, handles, n_destinations, payload, n_bytes);
		assert(r >= 0);

		/* receive */
		for (i = 0; i < n_destinations; i++) {
			r = client_recv(receivers[i], (void**)&reply_payload,
					&reply_len);
			assert(r >= 0);

			r = client_slice_release(receivers[i], reply_payload);
			assert(r >= 0);
		}
	}
	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	/* cleanup */
	sender = bus1_client_free(sender);

	for (i = 0; i < n_destinations; i++)
		receivers[i] = bus1_client_free(receivers[i]);

	return (time_end - time_start) / iterations;
}

int test_io(void)
{
	test_basic();
	fprintf(stderr, "it took %lu ns to send nothing to no one\n",
		test_iterate(10000, 0, 0));
	fprintf(stderr, "it took %lu ns for no dests\n",
		test_iterate(10000, 0, 1024));
	fprintf(stderr, "it took %lu ns for one dest\n",
		test_iterate(10000, 1, 1024));
	fprintf(stderr, "it took %lu ns per dest for 32 dests\n",
		test_iterate(10000, 32, 1024) / 32);
	fprintf(stderr, "it took %lu ns per dest for 64 dests\n",
		test_iterate(10000, 64, 1024) / 64);
	fprintf(stderr, "it took %lu ns per dest for 1000 dests\n",
		test_iterate(1000, 1000, 1024) / 1000);

	fprintf(stderr, "\n\n");

	return TEST_OK;
}
