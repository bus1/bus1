/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "test.h"

#define MAX_DESTINATIONS (256)

static inline uint64_t nsec_from_clock(clockid_t clock)
{
	struct timespec ts;
	int r;

	r = clock_gettime(clock, &ts);
	assert(r >= 0);
	return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static void test_one_uds(int uds[2], void *payload, size_t n_bytes)
{
	int r;

	/* send */
	r = write(uds[0], payload, n_bytes);
	assert(r == n_bytes);

	/* receive */
	r = recv(uds[1], payload, n_bytes, 0);
	assert(r == n_bytes);
}

static uint64_t test_iterate_uds(unsigned int iterations, size_t n_bytes)
{
	uint64_t time_start, time_end;
	char payload[n_bytes];
	unsigned int i;
	int uds[2];
	int r;

	/* create socket pair */
	r = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, uds);
	assert(r >= 0);

	/* caches */
	test_one_uds(uds, payload, n_bytes);

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++)
		test_one_uds(uds, payload, n_bytes);
	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	/* cleanup */
	close(uds[0]);
	close(uds[1]);

	return (time_end - time_start) / iterations;
}

static void test_one(int fd1,
		     int *fds,
		     uint64_t *handles,
		     unsigned int n_destinations,
		     char *payload,
		     size_t n_bytes)
{
	struct iovec vec = { payload, n_bytes };
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	size_t i;
	int r;

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)handles,
		.ptr_errors		= 0,
		.n_destinations		= n_destinations,
		.ptr_vecs		= (unsigned long)&vec,
		.n_vecs			= 1,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	for (i = 0; i < n_destinations; ++i) {
		cmd_recv = (struct bus1_cmd_recv){
			.flags = 0,
			.max_offset = -1,
		};
		r = bus1_ioctl_recv(fds[i], &cmd_recv);
		assert(r >= 0);
		assert(cmd_recv.msg.type == BUS1_MSG_DATA);
		assert(cmd_recv.msg.n_bytes == n_bytes);

		r = bus1_ioctl_slice_release(fds[i],
					     (uint64_t *)&cmd_recv.msg.offset);
		assert(r >= 0);
	}
}

static uint64_t test_iterate(unsigned int iterations,
			     unsigned int n_destinations,
			     size_t n_bytes)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	const uint8_t *maps[MAX_DESTINATIONS + 1];
	uint64_t handles[MAX_DESTINATIONS + 1];
	size_t n_maps[MAX_DESTINATIONS + 1];
	int r, fds[MAX_DESTINATIONS + 1];
	uint64_t time_start, time_end;
	char payload[n_bytes];
	size_t i;

	assert(n_destinations <= MAX_DESTINATIONS);

	/* setup */
	fds[0] = test_open(&maps[0], &n_maps[0]);

	for (i = 1; i < sizeof(fds) / sizeof(*fds); ++i) {
		fds[i] = test_open(&maps[i], &n_maps[i]);

		cmd_transfer = (struct bus1_cmd_handle_transfer){
			.flags			= 0,
			.src_handle		= 0x100,
			.dst_fd			= fds[0],
			.dst_handle		= BUS1_HANDLE_INVALID,
		};
		r = bus1_ioctl_handle_transfer(fds[i], &cmd_transfer);
		assert(r >= 0);
		handles[i] = cmd_transfer.dst_handle;
	}

	/* caches */
	test_one(fds[0], fds + 1, handles + 1, n_destinations, payload,
		 n_bytes);

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++)
		test_one(fds[0], fds + 1, handles + 1, n_destinations, payload,
			 n_bytes);
	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	for (i = 0; i < sizeof(fds) / sizeof(*fds); ++i)
		test_close(fds[i], maps[i], n_maps[i]);

	return (time_end - time_start) / iterations;
}

static void test_io(void)
{
	unsigned long base;
	unsigned int i;

	fprintf(stderr, "UDS took %lu ns without payload\n",
		test_iterate_uds(100000, 0));
	fprintf(stderr, "UDS took %lu ns\n",
		test_iterate_uds(100000, 1024));

	base = test_iterate(1000000, 0, 1024);

	fprintf(stderr, "it took %lu ns for no destinations\n", base);
	fprintf(stderr,
		"it took %lu ns + %lu ns for one destination without payload\n",
		base, test_iterate(100000, 1, 0) - base);
	fprintf(stderr, "it took %lu ns + %lu ns for one destination\n", base,
		test_iterate(100000, 1, 1024) - base);

	for (i = 1; i < 9; ++i) {
		unsigned int dests = 1UL << i;

		fprintf(stderr, "it took %lu ns + %lu ns per destination for %u destinations\n",
			base, (test_iterate(100000 >> i, dests, 1024) - base) / dests, dests);
	}
}

int main(int argc, char **argv)
{
	int r;

	r = test_parse_argv(argc, argv);
	if (r > 0) {
		test_io();
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
