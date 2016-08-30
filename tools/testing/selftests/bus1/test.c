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
#include <fcntl.h>
#include <getopt.h>
#include <linux/bus1.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include "test.h"

#define N_TESTS (sizeof(tests) / sizeof(tests[0]))

static const char *arg_module = "bus1";
static const char *arg_test;
char *test_path;

int c_sys_clone(unsigned long flags, void *child_stack)
{
#if defined(__s390__) || defined(__CRIS__)
	return (int)syscall(__NR_clone, child_stack, flags);
#else
	return (int)syscall(__NR_clone, flags, child_stack);
#endif
}

static int fork_and_run(const struct test *test)
{
	pid_t pid;
	int r;

	pid = fork();
	assert(pid >= 0);

	if (pid == 0) {
		r = test->main();
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

static int run_one(const struct test *test)
{
	size_t i, line_len;
	int r;

	/* print test name, aligned */
	line_len = 12 + strlen(test->name);
	fprintf(stdout, "Testing: `%s' ", test->name);
	for (i = line_len; i < 60; ++i)
		fprintf(stdout, ".");
	fprintf(stdout, "\n\n");
	fflush(stdout);

	/* run test */
	r = fork_and_run(test);

	/* print result */
	if (r == TEST_OK || r == TEST_SKIP)
		/* scroll down; move right */
		fprintf(stdout, "\r\e[2T\e[60C %s\n",
			r == TEST_OK ? "OK" : "SKIP");
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
		if (!strcmp(test, tests[i].name)) {
			r = run_one(&tests[i]);
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
		r = run_one(&tests[i]);
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
	int c;

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
				fprintf(stderr, "\t%s\n", tests[i].name);

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

	return 1;
}

int main(int argc, char **argv)
{
	size_t len;
	int r;

	r = parse_argv(argc, argv);
	if (r <= 0)
		goto exit;

	/* store cdev-path for tests to access ("/dev/<module>") */
	len = strlen(arg_module);
	test_path = alloca(len + 6);
	strcpy(test_path, "/dev/");
	strcpy(test_path + 5, arg_module);

	/* run selected test or all */
	if (arg_test)
		r = run_test(arg_test);
	else
		r = run_all();

exit:
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
