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

#define N_DESTS (512)
#define N_ITERATIONS (100000)
#define PAYLOAD_SIZE (1024)

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
				size_t len_payload, bool reply)
{
	uint8_t data[len_payload];
	struct b1_client *client = NULL;
	struct b1_client *clients[n_dests];
	uint64_t dests[n_dests];
	uint64_t time_start, time_end;
	void *ptr_payload = NULL;
	unsigned i, iterations = N_ITERATIONS;
	int r;

	assert(mount_path);
	assert(!reply || n_dests == 1);
	assert(n_dests < N_ITERATIONS);

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);

	r = b1_client_connect(client, NULL, 0);
	assert(r >= 0);

	for (i = 0; i < n_dests; i++) {
		clients[i] = NULL;
		r = b1_client_new_from_mount(&clients[i], mount_path);
		assert(r >= 0);
		assert(clients[i]);

		r = b1_client_connect(clients[i], NULL, 0);
		assert(r >= 0);

		dests[i] = r;
	}

	if (n_dests == 0)
		iterations *= 10;
	else
		iterations /= n_dests;

	if (len_payload > 0)
		ptr_payload = data;

	r = b1_client_send(client, dests, n_dests, ptr_payload, len_payload);
	assert(r >= 0);

	time_start = usec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++) {
		b1_client_send(client, dests, n_dests, ptr_payload, len_payload);
		if (reply) {
			size_t offset;

			b1_client_recv(client, &offset);
			b1_client_slice_release(client, offset);
		}
	}
	time_end = usec_from_clock(CLOCK_THREAD_CPUTIME_ID);

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

	return ((time_end - time_start) * 1000) / iterations;
}

static void test_peer_api(const char *mount_path)
{
	struct b1_client *client1 = NULL, *client2 = NULL;
	const char *name1 = "foo", *name2 = "bar";
	const char *names[] = { name1, name2, name2, name1};
	uint64_t dests[2] = { };
	uint64_t id1, id2, offset;
	unsigned i;
	int r;

	/* connection */
	r = b1_client_new_from_mount(&client1, mount_path);
	assert(r >= 0);
	assert(client1);

	id1 = b1_client_connect(client1, NULL, 0);
	assert(id1 > 0);

	r = b1_client_disconnect(client1);
	assert(r >= 0);

	client1 = b1_client_free(client1);
	assert(!client1);

	r = b1_client_new_from_mount(&client1, mount_path);
	assert(r >= 0);
	assert(client1);

	id2 = b1_client_connect(client1, names, 2);
	assert(id2 > 0);
	assert(id1 != id2);

	r = b1_client_connect(client1, names, 2);
	assert(r == -EISCONN);

	r = b1_client_connect(client1, names, 1);
	assert(r == -EREMCHG);

	r = b1_client_connect(client1, names, 3);
	assert(r == -EREMCHG);

	r = b1_client_connect(client1, &names[1], 2);
	assert(r == -EREMCHG);

	r = b1_client_connect(client1, &names[1], 1);
	assert(r == -EREMCHG);

	r = b1_client_connect(client1, NULL, 0);
	assert(r == -EREMCHG);

	r = b1_client_connect(client1, &names[2], 2);
	assert(r == -EISCONN);

	r = b1_client_new_from_mount(&client2, mount_path);
	assert(r >= 0);
	assert(client2);

	r = b1_client_connect(client2, NULL, 0);
	assert(r > 0);

	/* resolution */
	r = b1_client_resolve(client1, &id1, name1);
	assert(r >= 0);
	assert(id1 == id2);

	r = b1_client_resolve(client1, &id1, name2);
	assert(r >= 0);
	assert(id1 == id2);

	r = b1_client_resolve(client1, &id1, "unknown name");
	assert(r == -ENXIO);
	assert(id1 == id2);

	/* tracking */
	r = b1_client_track(client1, id1);
	assert(r == -ELOOP);

	r = b1_client_track(client1, -1);
	assert(r == -ENXIO);

	r = b1_client_track(client2, id1);
	assert(r >= 0);

	r = b1_client_track(client2, id1);
	assert(r == -EALREADY);

	r = b1_client_untrack(client2, id1);
	assert(r >= 0);

	r = b1_client_untrack(client2, id1);
	assert(r == -ENXIO);

	r = b1_client_track(client2, id1);
	assert(r >= 0);

	/* send, receive and free */
	r = b1_client_recv(client1, NULL);
	assert(r == -EAGAIN);

	dests[0] = id1;
	r = b1_client_send(client1, dests, 1, NULL, 0);
	assert(r >= 0);

	r = b1_client_recv(client1, &offset);
	assert(r == 24);

	r = b1_client_slice_release(client1, offset - 1);
	assert(r == -ENXIO);

	r = b1_client_slice_release(client1, offset + 1);
	assert(r == -ENXIO);

	r = b1_client_slice_release(client1, offset);
	assert(r >= 0);

	r = b1_client_slice_release(client1, offset);
	assert(r == -ENXIO);

	r = b1_client_recv(client1, NULL);
	assert(r == -EAGAIN);

	r = b1_client_send(client1, dests, 1, NULL, 0);
	assert(r >= 0);

	r = b1_client_send(client1, dests, 1, NULL, 0);
	assert(r >= 0);

	dests[1] = id1;
	r = b1_client_send(client1, dests, 2, NULL, 0);
	assert(r == -ENOTUNIQ);

	r = b1_client_recv(client1, NULL);
	assert(r == 24);

	r = b1_client_recv(client1, NULL);
	assert(r == 24);

	r = b1_client_recv(client1, NULL);
	assert(r == -EAGAIN);

	/* cleanup */
	r = b1_client_disconnect(client1);
	assert(r >= 0);

	client1 = b1_client_free(client1);
	assert(!client1);

	r = b1_client_disconnect(client2);
	assert(r >= 0);

	client2 = b1_client_free(client2);
	assert(!client2);
}

int test_peer(const char *mount_path)
{
	unsigned i;
	int r;

	test_peer_api(mount_path);

	r = test_peer_sequential(mount_path, 0, 0, false);
	fprintf(stderr, "noop send takes %zu ns\n", r);

	r = test_peer_sequential(mount_path, 1, 0, false);
	fprintf(stderr, "unicast send without payload takes %zu ns\n", r);

	r = test_peer_sequential(mount_path, 1, 0, true);
	fprintf(stderr, "unicast send/recv without payload takes %zu ns\n", r);

	for (i = 2; i <= N_DESTS; i *= 2) {
		r = test_peer_sequential(mount_path, i, 0, false);
		assert(r >= 0);

		fprintf(stderr, "multicast %zu messages without payload in "
                        "%zu ns per destination\n", i, r / i);
	}

	r = test_peer_sequential(mount_path, 1, PAYLOAD_SIZE, false);
	fprintf(stderr, "unicast send with %d byte payload takes %zu ns\n",
		PAYLOAD_SIZE, r);

	r = test_peer_sequential(mount_path, 1, PAYLOAD_SIZE, true);
	fprintf(stderr, "unicast send/recv with %d byte payload takes %zu "
		"ns\n", PAYLOAD_SIZE, r);

	for (i = 2; i <= N_DESTS; i *= 2) {
		r = test_peer_sequential(mount_path, i, PAYLOAD_SIZE, false);
		assert(r >= 0);

		fprintf(stderr, "multicast %zu messages with %d byte payload "
			"in %zu ns per destination\n", i, PAYLOAD_SIZE, r / i);
	}

	fprintf(stderr, "\n\n");

	return B1_TEST_OK;
}
