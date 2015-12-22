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
#include <time.h>
#include "b1-test.h"

#define b1_usec_from_nsec(_nsec) ((_nsec) / UINT64_C(1000))
#define b1_usec_from_msec(_msec) ((_msec) * UINT64_C(1000))
#define b1_usec_from_sec(_sec) b1_usec_from_msec((_sec) * UINT64_C(1000))
#define b1_usec_from_timespec(_ts) (b1_usec_from_sec((_ts)->tv_sec) + b1_usec_from_nsec((_ts)->tv_nsec))

static inline uint64_t usec_from_clock(clockid_t clock) {
        struct timespec ts;
        int r;

        r = clock_gettime(clock, &ts);
        assert(r >= 0);
        return b1_usec_from_timespec(&ts);
}

/* test the degenerate un-contended case, this is only interesting in as far as
 * it gives us a baseline of how fast things can be in the best case */
static int test_peer_sequential(const char *mount_path, size_t n_dests,
				unsigned iterations, bool payload, bool reply)
{
	uint8_t data[1024] = {};
	struct b1_client *client = NULL;
	uint64_t dests[n_dests], id;
	uint64_t time_start, time_end;
	void *ptr_payload = NULL;
	size_t len_payload = 0;
	unsigned i;
	int r;

	assert(!reply || n_dests == 1);

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	id = b1_client_connect(client, NULL, 0);
	assert(id > 0);

	for (i = 0; i < n_dests; i ++)
		dests[i] = id;

	if (payload) {
		ptr_payload = data;
		len_payload = sizeof(data);
	}

	r = b1_client_send(client, dests, n_dests, ptr_payload, len_payload);
	assert(r >= 0);

	time_start = usec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++) {
		b1_client_send(client, dests, n_dests, ptr_payload, len_payload);
		if (reply)
			b1_client_recv(client);
	}
	time_end = usec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);

	return time_end - time_start;
}

static int test_peer_api(const char *mount_path)
{
	struct b1_client *client = NULL;
	const char *name1 = "foo", *name2 = "bar";
	const char *names[] = { name1, name2 };
	uint64_t dests[3] = { };
	uint64_t id1, id2;
	unsigned i;
	int r;

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	id1 = b1_client_connect(client, NULL, 0);
	assert(id1 > 0);

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	id2 = b1_client_connect(client, names, 2);
	assert(id2 > 0);
	assert(id1 != id2);

	r = b1_client_resolve(client, &id1, name1);
	assert(r >= 0);
	assert(id1 == id2);

	r = b1_client_resolve(client, &id1, name2);
	assert(r >= 0);
	assert(id1 == id2);

	r = b1_client_recv(client);
	assert(r == -EAGAIN);

	dests[0] = id1;
	r = b1_client_send(client, dests, 1, NULL, 0);
	assert(r >= 0);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == -EAGAIN);

	dests[1] = id1;
	dests[2] = id1;
	r = b1_client_send(client, dests, 1, NULL, 0);
	assert(r >= 0);

	r = b1_client_send(client, dests, 3, NULL, 0);
	assert(r >= 0);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == -EAGAIN);

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);

	return B1_TEST_OK;
}

int test_peer(const char *mount_path)
{
	unsigned i;
	int r;

	r = test_peer_api(mount_path);
	if (r < 0)
		return r;

	r = test_peer_sequential(mount_path, 0, 10000000, false, false);
	fprintf(stderr, "noop send takes %zu ns\n", r / 10000);

	r = test_peer_sequential(mount_path, 1, 10000, false, false);
	fprintf(stderr, "unicast send without payload takes %zu ns\n",
		r / 10);

	r = test_peer_sequential(mount_path, 1, 10000, false, true);
	fprintf(stderr, "unicast send/recv without payload takes %zu ns\n",
		r / 10);

	for (i = 2; i <= 128; i *= 4) {
		r = test_peer_sequential(mount_path, i, 1000, false, false);
		assert(r >= 0);

		fprintf(stderr, "multicast %zu messages without payload in "
                        "%zu ns per destination\n", i, r / i);
	}

	r = test_peer_sequential(mount_path, 1, 10000, true, false);
	fprintf(stderr, "unicast send with payload takes %zu ns\n",
		r / 10);

	r = test_peer_sequential(mount_path, 1, 10000, true, true);
	fprintf(stderr, "unicast send/recv with payload takes %zu ns\n",
		r / 10);

	for (i = 2; i <= 128; i *= 4) {
		r = test_peer_sequential(mount_path, i, 1000, true, false);
		assert(r >= 0);

		fprintf(stderr, "multicast %zu messages with payload in %zu ns "
			"per destination\n", i, r / i);
	}

	return B1_TEST_OK;
}
