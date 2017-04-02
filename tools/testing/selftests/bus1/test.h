#ifndef __TEST_H
#define __TEST_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/* include standard environment for all tests */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/bus1.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bus1-ioctl.h"

static char *test_path;
static char *test_arg_module = "bus1";

#define c_align_to(_val, _to) (((_val) + (_to) - 1) & ~((_to) - 1))

static inline int test_parse_argv(int argc, char **argv)
{
	enum {
		ARG_MODULE = 0x100,
	};
	static const struct option options[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "module",	required_argument,	NULL, ARG_MODULE },
		{}
	};
	char *t;
	int c;

	t = getenv("BUS1EXT");
	if (t) {
		test_arg_module = malloc(strlen(t) + 4);
		assert(test_arg_module);
		strcpy(test_arg_module, "bus");
		strcpy(test_arg_module + 3, t);
	}

	while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
		switch (c) {
		case 'h':
			fprintf(stderr,
				"Usage: %s [OPTIONS...] ...\n\n"
				"Run bus1 test.\n\n"
				"\t-h, --help         Print this help\n"
				"\t    --module=bus1  Module to use\n"
				, program_invocation_short_name);

			return 0;

		case ARG_MODULE:
			test_arg_module = optarg;
			break;

		case '?':
			/* fallthrough */
		default:
			return -EINVAL;
		}
	}

	/* store cdev-path for tests to access ("/dev/<module>") */
	free(test_path);
	test_path = malloc(strlen(test_arg_module) + 6);
	assert(test_path);
	strcpy(test_path, "/dev/");
	strcpy(test_path + 5, test_arg_module);

	return 1;
}

static inline int test_open(const uint8_t **mapp, size_t *n_mapp)
{
	const size_t size = 16UL * 1024UL;
	int fd;

	fd = open(test_path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	assert(fd >= 0);

	*mapp = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	assert(*mapp != MAP_FAILED);

	*n_mapp = size;
	return fd;
}

static inline void test_close(int fd, const uint8_t *map, size_t n_map)
{
	munmap((void *)map, n_map);
	close(fd);
}

#endif /* __TEST_H */
