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

/**
 * kref: Implement 'struct kref' using refcount_t API breakage
 *
 * Since 4.11 kernel uses refcount_t to implement struct kref instead of atomic_t.
 * Following macro fixes semantics on newer kernels while keeping compatibily with old API.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define ATOMIC_READ_ACCESS_KREF(KREF) atomic_read(KREF)
#else
#define ATOMIC_READ_ACCESS_KREF(KREF) atomic_read(KREF.refs)
#endif

#endif /* __BUS1_TESTS_H */
