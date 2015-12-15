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
	int r;

	r = b1_client_new_from_mount(&client, mount_path);
	assert(r >= 0);
	assert(client);

	client = b1_client_free(client);
	assert(!client);

	return B1_TEST_OK;
}
