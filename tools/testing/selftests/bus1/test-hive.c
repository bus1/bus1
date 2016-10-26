/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include "test.h"

#define N_CHILDREN (1000)
#define N_SIBLINGS (100)

struct bus1_child {
	struct bus1_peer *peer;
	uint64_t siblings[N_SIBLINGS];
};

static void *child_thread(void *p)
{
	struct bus1_child *child = p;

	assert(child);

	bus1_peer_free(child->peer);

	return NULL;
}

int test_hive(void)
{
	struct bus1_peer *parent;
	struct bus1_child children[N_CHILDREN];
	uint64_t child_handles[N_CHILDREN];
	size_t n_children = 0;
	unsigned int i;
	int r;

	r = bus1_peer_new_from_path(&parent, test_path);
	assert(r >= 0);

	for (i = 0; i < N_CHILDREN; i++) {
		uint64_t node =
			BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;

		r = bus1_peer_new_from_path(&children[i].peer, test_path);
		assert(r >= 0);

		child_handles[i] = BUS1_HANDLE_INVALID;
		r = bus1_peer_handle_transfer(children[i].peer,
					      parent,
					      &node,
					      &child_handles[i]);
		assert(r >= 0);
	}

	for (i = 0; i < N_CHILDREN; i++) {
		unsigned int j;

		for (j = 0; j < N_SIBLINGS; j++) {
			unsigned int k = (i + j + 1) % N_CHILDREN;

			children[i].siblings[j] = BUS1_HANDLE_INVALID;

			r = bus1_peer_handle_transfer(parent,
						      children[i].peer,
						      &child_handles[k],
						      &children[i].siblings[j]);
			if (r < 0)
				fprintf(stderr, "%d\n", r);
			assert(r >= 0);
		}
	}

	for (i = 0; i < N_CHILDREN; i++) {
		pthread_attr_t a;
		pthread_t t;

		r = pthread_attr_init(&a);
		assert(r == 0);

		r = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
		assert(r == 0);

		r = pthread_create(&t, &a, child_thread, &children[i]);
		assert(r == 0);

		++n_children;

		r = pthread_attr_destroy(&a);
		assert(r == 0);
	}

	while (n_children) {
		struct bus1_cmd_recv recv = {};

		r = bus1_peer_recv(parent, &recv);
		assert(r >= 0 || r == -EAGAIN);

		if (r == -EAGAIN)
			continue;

		assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);

		--n_children;
	}

	bus1_peer_free(parent);

	return TEST_OK;
}
