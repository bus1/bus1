/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include "test.h"

#define N_CHILDREN (900)

static void *child_thread(void *p) {
	struct bus1_peer *child = p;

	assert(child);

	bus1_peer_free(child);

	return NULL;
}

int test_hive(void)
{
	struct bus1_peer *parent;
	struct bus1_peer *children[N_CHILDREN];
	uint64_t child_handles[N_CHILDREN];
	size_t n_children = 0;
	unsigned int i;
	int r;

	r = bus1_peer_new_from_path(&parent, test_path);
	assert(r >= 0);

	for (i = 0; i < N_CHILDREN; i ++) {
		uint64_t node =
			BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;

		r = bus1_peer_new_from_path(children + i, test_path);
		assert(r >= 0);

		child_handles[i] = BUS1_HANDLE_INVALID;
		r = bus1_peer_handle_transfer(children[i], parent, &node,
					      child_handles + i);
		assert(r >= 0);
	}

	for (i = 0; i < N_CHILDREN; i ++) {
		pthread_attr_t a;
		pthread_t t;

		r = pthread_attr_init(&a);
		assert(r == 0);

		r = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
		assert(r == 0);

		r = pthread_create(&t, &a, child_thread, children[i]);
		assert(r == 0);

		++ n_children;

		r = pthread_attr_destroy(&a);
		assert(r == 0);
	}

	while (n_children) {
		struct bus1_cmd_recv recv = {};

		r = bus1_peer_recv(parent, &recv);
		assert(r >= 0);
		assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);

		-- n_children;
	}

	bus1_peer_free(parent);

	return TEST_OK;
}
