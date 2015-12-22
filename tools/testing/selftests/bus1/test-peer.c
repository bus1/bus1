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
#include "b1-test.h"

int test_peer(const char *mount_path)
{
	struct b1_client *client = NULL;
	const char *name1 = "foo", *name2 = "bar";
	const char *names[] = { name1, name2 };
	uint64_t dests[3] = { };
	uint64_t id1, id2;
	int r;

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	id1 = b1_client_connect(client, NULL, 0);
	assert(id1 >= 0);

	r = b1_client_disconnect(client);
	assert(r >= 0);

	client = b1_client_free(client);
	assert(!client);

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	id2 = b1_client_connect(client, names, 2);
	assert(id2 >= 0);
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
	r = b1_client_send(client, dests, 1);
	assert(r >= 0);

	r = b1_client_recv(client);
	assert(r == 24);

	r = b1_client_recv(client);
	assert(r == -EAGAIN);

	dests[1] = id1;
	dests[2] = id1;
	r = b1_client_send(client, dests, 1);
	assert(r >= 0);

	r = b1_client_send(client, dests, 3);
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
