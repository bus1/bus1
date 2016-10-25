#ifndef __BUS1_TESTS_H
#define __BUS1_TESTS_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Kernel Selftests
 *
 * These tests are built into the kernel module itself if, and only if, the
 * required configuration is selected. On every module load, the selftests will
 * be run. On production builds, this option should not be selected.
 */

#include <linux/kernel.h>

#if IS_ENABLED(CONFIG_BUS1_TESTS)
int bus1_tests_run(void);
#else
static inline int bus1_tests_run(void)
{
	return 0;
}
#endif

#endif /* __BUS1_TESTS_H */
