#ifndef __B1_TEST_H
#define __B1_TEST_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/* include standard environment for all tests */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include "b1-client.h"

struct b1_test {
	const char *name;
	int (*main) (const char *mount_path);
};

int test_filesystem(const char *mount_path);
int test_peer(const char *mount_path);

static const struct b1_test b1_tests[] = {
	{ .name = "filesystem", .main = test_filesystem },
	{ .name = "peer", .main = test_peer },
};

#endif /* __B1_TEST_H */
