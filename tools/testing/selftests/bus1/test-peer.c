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
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "b1-test.h"

#define N_DESTS (512)
#define N_ITERATIONS (100000ULL)
#define PAYLOAD_SIZE (1024)
#define CONNECT_FLAGS (BUS1_CONNECT_FLAG_CLIENT | BUS1_CONNECT_FLAG_QUERY)
#define POOL_SIZE (1024 * 1024 * 32)

/*
static inline uint64_t nsec_from_clock(clockid_t clock)
{
	struct timespec ts;
	int r;

	r = clock_gettime(clock, &ts);
	assert(r >= 0);
	return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

// by way of comparison test unicast message passing on unix domain sockets,
// we expect this to be faster than bus1, but the aim is of course to be
// competitive even in the degenerate unicast case
static int test_uds_sequential(size_t len_payload)
{
	uint64_t time_start, time_end, i, iterations = N_ITERATIONS;
	uint8_t payload[PAYLOAD_SIZE] = {};
	struct iovec vec = {
		.iov_base = payload,
		.iov_len = len_payload
	};
	int r, uds[2], one = 1;

	assert(len_payload <= PAYLOAD_SIZE);

	r = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, uds);
	assert(r >= 0);

	r = setsockopt(uds[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
	assert(r >= 0);

	r = writev(uds[0], &vec, 1);
	assert(r == len_payload);

	r = readv(uds[1], &vec, 1);
	assert(r == len_payload);

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++) {
		r = writev(uds[0], &vec, 1);
		assert(r == len_payload);

		r = readv(uds[1], &vec, 1);
		assert(r == len_payload);
	}

	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	close(uds[0]);
	close(uds[1]);

	return (time_end - time_start) / iterations;
}

// test the degenerate un-contended case, this is only interesting in as far as
// it gives us a baseline of how fast things can be in the best case
static int test_peer_sequential(const char *path, size_t n_dests,
				size_t len_payload)
{
	struct b1_client *client = NULL;
	struct b1_client *clients[n_dests];
	uint64_t dests[n_dests];
	uint64_t time_start, time_end, i, iterations = N_ITERATIONS;
	uint8_t payload[PAYLOAD_SIZE] = {};
	struct iovec vec = {
		.iov_base = payload,
		.iov_len = len_payload
	};
	int r;

	assert(path);
	assert(n_dests < N_ITERATIONS);
	assert(len_payload <= PAYLOAD_SIZE);

	r = b1_client_new_from_path(&client, path);
	assert(r >= 0);

	r = b1_client_connect(client, CONNECT_FLAGS, POOL_SIZE, NULL, 0);
	assert(r >= 0);

	for (i = 0; i < n_dests; i++) {
		clients[i] = NULL;
		r = b1_client_new_from_path(&clients[i], path);
		assert(r >= 0);
		assert(clients[i]);

		r = b1_client_connect(clients[i], CONNECT_FLAGS, POOL_SIZE,
				      NULL, 0);
		assert(r >= 0);

		dests[i] = r;
	}

	// make sure test-runs take a reasonable amount of time
	if (n_dests > 0)
		iterations /= n_dests;

	r = b1_client_send(client, 0, dests, n_dests, &vec, 1);
	assert(r >= 0);

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++) {
		size_t j;

		r = b1_client_send(client, 0, dests, n_dests, &vec, 1);
		assert(r >= 0);


		for (j = 0; j < n_dests; ++j) {
			r = b1_client_recv(clients[j], 0, NULL, NULL);
			assert(r >= 0);
		}
	}
	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	for (i = 0; i < n_dests; i++) {
		r = b1_client_disconnect(clients[i]);
		assert(r >= 0);

		clients[i] = b1_client_free(clients[i]);
		assert(!clients[i]);
	}

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);

	return (time_end - time_start) / iterations;
}
*/

static void test_peer_api(const char *path)
{
	struct b1_client *client;
	int r;

	r = b1_client_new_from_path(&client, path);
	assert(r >= 0);
	assert(client);

	r = b1_client_connect(client, CONNECT_FLAGS, POOL_SIZE);
	assert(r >= 0);

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);
}

int test_peer(const char *path)
{
	unsigned i;
	int r, with, without;

	test_peer_api(path);

	/* initialize all caches
	r = test_peer_sequential(path, N_DESTS, PAYLOAD_SIZE);
	r = test_uds_sequential(PAYLOAD_SIZE);
	assert(r >= 0);

	r = test_peer_sequential(path, 0, 0);
	assert(r >= 0);
	fprintf(stderr, "noop send takes %zu ns\n", r);

	without = test_uds_sequential(0);
	assert(without >= 0);
	with = test_uds_sequential(PAYLOAD_SIZE);
	assert(with >= 0);
	fprintf(stderr, "unicast UDS send without payload takes %d ns, with %d "
		"byte payload is %d ns %s\n",
		without, PAYLOAD_SIZE,
		with > without ? with - without : without - with,
		with > without ? "slower" : "faster");

	without = test_peer_sequential(path, 1, 0);
	assert(without >= 0);
	with = test_peer_sequential(path, 1, PAYLOAD_SIZE);
	assert(with >= 0);
	fprintf(stderr, "unicast send without payload takes %d ns, with %d "
		"byte payload is %d ns %s\n",
		without, PAYLOAD_SIZE,
		with > without ? with - without : without - with,
		with > without ? "slower" : "faster");

	for (i = 2; i <= N_DESTS; i *= 2) {
		without = test_peer_sequential(path, i, 0);
		assert(without >= 0);
		with = test_peer_sequential(path, i, PAYLOAD_SIZE);
		assert(with >= 0);

		fprintf(stderr, "multicast %3u messages without payload in "
			"%4d ns per destination, with %d byte payload is %3d "
			"ns %s\n", i, without / i, PAYLOAD_SIZE,
		with > without ? (with - without) / i : (without - with) / i,
			with > without ? "slower" : "faster");
	}

	fprintf(stderr, "\n\n");
*/
	return B1_TEST_OK;
}
