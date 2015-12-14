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

int test_filesystem(const char *mount_path)
{
	bool found_bus = false, found_dot = false, found_dotdot = false;
	struct dirent *de;
	DIR *dir;
	int r;

	/* make sure the mount-path exists */
	r = access(mount_path, F_OK);
	assert(r == 0);

	/* iterate directory; verify only known files are found */
	dir = opendir(mount_path);
	assert(dir);

	for (;;) {
		de = readdir(dir);
		if (!de)
			break;

		if (!strcmp(de->d_name, ".")) {
			assert(!found_dot);
			found_dot = true;
		} else if (!strcmp(de->d_name, "..")) {
			assert(!found_dotdot);
			found_dotdot = true;
		} else if (!strcmp(de->d_name, "bus")) {
			assert(!found_bus);
			found_bus = true;
		} else {
			assert(0);
		}
	}

	/* make sure all expected files were found */
	assert(found_dot);
	assert(found_dotdot);
	assert(found_bus);

	return 0;
}
