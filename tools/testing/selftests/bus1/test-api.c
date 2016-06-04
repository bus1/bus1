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
#include "test.h"

/* make sure /dev/busX exists, is a cdev and accessible */
static void test_api_cdev(void)
{
	struct stat st;
	int r;

	r = access(test_path, F_OK);
	assert(r >= 0);

	r = stat(test_path, &st);
	assert(r >= 0);
	assert((st.st_mode & S_IFMT) == S_IFCHR);

	r = open(test_path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	assert(r >= 0);
	close(r);
}

/* make sure we can open and use /dev/busX via bus1_client */
static void test_api_client(void)
{
	struct bus1_client *c;
	int r, fd;

	r = bus1_client_new_from_path(&c, test_path);
	assert(r >= 0);

	c = bus1_client_free(c);
	assert(!c);

	c = bus1_client_free(NULL);
	assert(!c);

	fd = open(test_path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	assert(fd >= 0);

	r = bus1_client_new_from_fd(&c, fd); /* consumes @fd on success */
	assert(r >= 0);

	c = bus1_client_free(c);
	assert(!c);
}

int client_query(struct bus1_client *client)
{
	struct bus1_cmd_peer_init query = {};
	int r;

	r = bus1_client_ioctl(client, BUS1_CMD_PEER_QUERY, &query);
	if (r < 0)
		return r;

	return query.pool_size;
}

/* make sure basic connect + clone works */
static void test_api_connect(void)
{
	struct bus1_client *c1, *c2;
	uint64_t node, handle;
	int r, fd;

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);

	/* verify clone fails if origin is unconnected */

	node = BUS1_HANDLE_INVALID;
	handle = BUS1_HANDLE_INVALID;
	fd = -1;
	r = bus1_client_clone(c1, &node, &handle, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r < 0);
	assert(node == BUS1_HANDLE_INVALID);
	assert(handle == BUS1_HANDLE_INVALID);
	assert(fd == -1);

	r = client_query(c1);
	assert(r == -ENOTCONN);

	/* connect @c1 properly */

	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = client_query(c1);
	assert(r == BUS1_CLIENT_POOL_SIZE);

	/* disconnect and reconnect @c1 */

	c1 = bus1_client_free(c1);
	assert(!c1);

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);

	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	/* clone new peer from @c1 and create @c2 from it */

	r = bus1_client_clone(c1, &node, &handle, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);
	assert(node != BUS1_HANDLE_INVALID);
	assert(handle != BUS1_HANDLE_INVALID);
	assert(fd >= 0);

	r = bus1_client_new_from_fd(&c2, fd);
	assert(r >= 0);

	r = client_query(c2);
	assert(r == BUS1_CLIENT_POOL_SIZE);

	c2 = bus1_client_free(c2);
	assert(!c2);

	/* drop @c1 eventually */

	c1 = bus1_client_free(c1);
	assert(!c1);
}


/* make sure we can set + get seed */
static void test_api_seed(void)
{
	struct bus1_client *client;
	char *payload = "WOOF";
	struct iovec vec = {
		.iov_base = payload,
		.iov_len = strlen(payload) + 1,
	};
	uint64_t handles[] = { BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE };
	struct bus1_cmd_send send = {
		.flags = BUS1_SEND_FLAG_SEED,
		.ptr_vecs = (uintptr_t)&vec,
		.n_vecs = 1,
		.ptr_handles = (uintptr_t)&handles,
		.n_handles = 1,
	};
	struct bus1_cmd_recv recv = {
		.flags = BUS1_RECV_FLAG_SEED,
	};
	void *slice;
	uint64_t handle_id;
	int r;

	r = bus1_client_new_from_path(&client, test_path);
	assert(r >= 0);

	r = bus1_client_init(client, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	r = bus1_client_mmap(client);
	assert(r >= 0);

	r = bus1_client_send(client, &send);
	assert(r >= 0);

	assert(handles[0] != 0);
	assert(handles[0] != BUS1_HANDLE_INVALID);
	assert(!(handles[0] & BUS1_NODE_FLAG_ALLOCATE));

	/* the seed can be replaced */
	r = bus1_client_send(client, &send);
	assert(r >= 0);

	/* the seed can not be passed the SILENT flag */
	send.flags |= BUS1_SEND_FLAG_SILENT;
	r = bus1_client_send(client, &send);
	assert(r == -EINVAL);

	r = bus1_client_recv(client, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);

	slice = bus1_client_slice_from_offset(client, recv.data.offset);
	assert(slice);

	assert(recv.data.n_bytes == strlen(payload) + 1);
	assert(strncmp(slice, payload, recv.data.n_bytes) == 0);
	handle_id = *(uint64_t*)((uint8_t*)slice + ((recv.data.n_bytes + 7) & ~(7ULL)));
	assert(handle_id != 0);
	assert(handle_id != BUS1_HANDLE_INVALID);
	assert(!(handle_id & BUS1_NODE_FLAG_ALLOCATE));

	client = bus1_client_free(client);
	assert(!client);
}

int test_api(void)
{
	test_api_cdev();
	test_api_client();
	test_api_connect();
	test_api_seed();
	return TEST_OK;
}
