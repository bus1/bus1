/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/*
 * Mount Tests
 * This test contains several short tests that verify mount-behavior. The basic
 * setup here clones a child-process within its own mount-namespace. Inside of
 * it we mount a separate bus1 domain and perform our tests on it, to not
 * corrupt the other tests.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include "b1-test.h"

static int test_teardown(void)
{
	size_t mountlen;
	char *file;
	DIR *dir;
	int r;

	/* forced teardown is only supported on non-standard builds */
	if (!strcmp(b1_filesystem, "bus1fs"))
		return B1_TEST_SKIP;

	mountlen = strlen(b1_mountpath);
	file = alloca(mountlen + 5);
	memcpy(file, b1_mountpath, mountlen);
	memcpy(file + mountlen, "/bus", 5);

	/* tear domain down */
	r = unlink(file);
	assert(r >= 0);

	/* make sure the domain still exists */
	r = access(b1_mountpath, F_OK);
	assert(r >= 0);

	/*
	 * If a domain is down, the whole directory must be inaccessible. That
	 * is, the unlink() operation not only deletes the file, but also makes
	 * sure the whole directory is inaccessible. This guarantees that we
	 * get ESHUTDOWN, instead of ENOENT/whatever.
	 */
	r = access(file, F_OK);
	assert(r < 0 && errno == ESHUTDOWN);

	/*
	 * If the domain is down, an opendir() might succeed (but if it
	 * doesn't, then it must be due to ESHUTDOWN), but any following
	 * readdir() *must* return ESHUTDOWN.
	 */
	dir = opendir(b1_mountpath);
	if (dir)
		assert(!readdir(dir));
	assert(errno == ESHUTDOWN);

	return B1_TEST_OK;
}

static int test_child(int (*child_func) (void))
{
	struct stat st1, st2;
	int r;

	/* make sure we don't propagate mounts back to the parent */
	r = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
	assert(r >= 0);

	r = stat(b1_mountpath, &st1);
	assert(r >= 0);

	/* mount fresh domain */
	r = mount(b1_filesystem,
		  b1_mountpath,
		  b1_filesystem,
		  MS_NOSUID | MS_NOEXEC | MS_NODEV,
		  NULL);
	assert(r >= 0);

	r = stat(b1_mountpath, &st2);
	assert(r >= 0);

	/* new domain must not equal parent domain */
	assert(st1.st_dev != st2.st_dev);

	return child_func();
}

static int test_clone(int (*child_func) (void))
{
	pid_t pid;
	int r;

	pid = b1_sys_clone(SIGCHLD | CLONE_NEWNS, NULL);
	assert(pid >= 0);

	if (pid == 0) {
		r = test_child(child_func);
		_exit(r);
	}

	pid = waitpid(pid, &r, 0);
	assert(pid > 0);
	assert(WIFEXITED(r));
	assert(WEXITSTATUS(r) == B1_TEST_OK || WEXITSTATUS(r) == B1_TEST_SKIP);

	return WEXITSTATUS(r);
}

int test_mount(const char *mount_path)
{
	int r, res = B1_TEST_OK;

	/*
	 * We need root to mount private domains. We could use user-namespaces,
	 * but those are usually not enabled for non-root on common distros.
	 */
	if (geteuid() != 0)
		return B1_TEST_SKIP;

	/*
	 * Run all mount-tests and fold the error-codes. If at least one test
	 * fails, we must return an error. If at least one test is skipped, we
	 * must return SKIP. Only if all pass, we pass.
	 */

	r = test_clone(test_teardown);
	if (r != B1_TEST_OK)
		res = res == B1_TEST_OK ? r : res == B1_TEST_SKIP ? r : res;

	return res;
}
