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

/* make sure basic connect + clone works */
static void test_api_connect(void)
{
	struct bus1_client *c1, *c2;
	uint64_t handle;
	int r, fd;

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);

	/* verify clone fails if origin is unconnected */

	handle = BUS1_HANDLE_INVALID;
	fd = -1;
	r = bus1_client_clone(c1, &handle, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r < 0);
	assert(fd == -1);
	assert(handle == BUS1_HANDLE_INVALID);

	/* connect @c1 properly */

	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	/* disconnect and reconnect @c1 */

	c1 = bus1_client_free(c1);
	assert(!c1);

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);

	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);

	/* clone new peer from @c1 and create @c2 from it */

	r = bus1_client_clone(c1, &handle, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);
	assert(fd >= 0);
	assert(handle != BUS1_HANDLE_INVALID);

	r = bus1_client_new_from_fd(&c2, fd);
	assert(r >= 0);

	c2 = bus1_client_free(c2);
	assert(!c2);

	/* drop @c1 eventually */

	c1 = bus1_client_free(c1);
	assert(!c1);
}

int test_api(void)
{
	test_api_cdev();
	test_api_client();
	test_api_connect();
	return TEST_OK;
}
