/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include "filesystem.h"
#include "main.h"

static int __init bus1_init(void)
{
	int r;

	r = sysfs_create_mount_point(fs_kobj, KBUILD_MODNAME);
	if (r)
		goto exit;

	r = bus1_fs_init();
	if (r < 0)
		goto exit_mount;

	pr_info("initialized\n");
	return 0;

exit_mount:
	sysfs_remove_mount_point(fs_kobj, KBUILD_MODNAME);
exit:
	pr_err("initialization failed: %d\n", r);
	return r;
}

static void __exit bus1_exit(void)
{
	bus1_fs_exit();
	sysfs_remove_mount_point(fs_kobj, KBUILD_MODNAME);
}

module_init(bus1_init);
module_exit(bus1_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bus based interprocess communication");
MODULE_ALIAS_FS(KBUILD_MODNAME "fs");
