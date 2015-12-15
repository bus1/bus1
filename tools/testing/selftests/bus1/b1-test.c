/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "b1-client.h"
#include "b1-test.h"

#define N_TESTS (sizeof(b1_tests) / sizeof(b1_tests[0]))

static const char *arg_module = "bus1";
static const char *arg_test = NULL;
const char *b1_filesystem = NULL;
const char *b1_mountpath = NULL;

static int fork_and_run(const struct b1_test *test, const char *mount_path)
{
	pid_t pid;
	int r;

	pid = fork();
	assert(pid >= 0);

	if (pid == 0) {
		r = test->main(mount_path);
		_exit(r);
	}

	pid = waitpid(pid, &r, 0);
	if (pid <= 0)
		return -ECHILD;
	else if (!WIFEXITED(r))
		return -ECHILD;
	else
		return WEXITSTATUS(r);
}

static int run_one(const struct b1_test *test)
{
	size_t i, line_len;
	int r;

	/* print test name, aligned */
	line_len = 12 + strlen(test->name);
	fprintf(stdout, "Testing: `%s' ", test->name);
	for (i = line_len; i < 60; ++i)
		fprintf(stdout, ".");
	fprintf(stdout, " \n\n");
	fflush(stdout);

	/* run test */
	r = fork_and_run(test, b1_mountpath);

	/* print result */
	if (r == B1_TEST_OK || r == B1_TEST_SKIP)
		/* scroll down; move right */
		fprintf(stdout, "\r\e[2T\e[60C %s\n",
			r == B1_TEST_OK ? "OK" : "SKIP");
	else
		fprintf(stdout, "\nERROR\n\n");

	return 0;
}

static int run_test(const char *test)
{
	size_t i;
	int r;

	assert(test);

	fprintf(stdout, "\nRun selected test:\n\n");

	for (i = 0; i < N_TESTS; ++i) {
		if (!strcmp(test, b1_tests[i].name)) {
			r = run_one(&b1_tests[i]);
			fprintf(stdout, "\n");
			return r;
		}
	}

	fprintf(stderr, "unknown test '%s'\n", test);
	return -ENXIO;
}

static int run_all(void)
{
	int r, res = 0;
	size_t i;

	fprintf(stdout, "\nRun all tests:\n\n");

	for (i = 0; i < N_TESTS; ++i) {
		r = run_one(&b1_tests[i]);
		if (r < 0 && res >= 0)
			res = r;
	}

	fprintf(stdout, "\n");

	return res;
}

static int parse_argv(int argc, char **argv)
{
	enum {
		ARG_MODULE = 0x100,
	};
	static const struct option options[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "module",	required_argument,	NULL, ARG_MODULE },
		{}
	};
	size_t i;
	int r, c;

	while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
		switch (c) {
		case 'h':
			fprintf(stderr,
				"Usage: %s [OPTIONS...] {TEST} ...\n\n"
				"Run bus1 tests. If no test is specified, "
				"all tests are run sequentially.\n\n"
				"\t-h, --help         Print this help\n"
				"\nTests:\n"
				, program_invocation_short_name);

			for (i = 0; i < N_TESTS; ++i)
				fprintf(stderr, "\t%s\n", b1_tests[i].name);

			return 0;

		case ARG_MODULE:
			arg_module = optarg;
			break;

		case '?':
			/* fallthrough */
		default:
			return -EINVAL;
		}
	}

	if (argc > optind)
		arg_test = argv[optind];

	r = asprintf((char **)&b1_filesystem, "%sfs", arg_module);
	assert(r >= 0);

	r = asprintf((char **)&b1_mountpath, "/sys/fs/%s", arg_module);
	assert(r >= 0);

	return 1;
}

int main(int argc, char **argv)
{
	int r;

	r = parse_argv(argc, argv);
	if (r <= 0)
		goto exit;

	if (arg_test)
		r = run_test(arg_test);
	else
		r = run_all();

exit:
	free((char *)b1_mountpath);
	free((char *)b1_filesystem);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
