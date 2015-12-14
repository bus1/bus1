/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/bus1.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "b1-client.h"

struct b1_client {
	int fd;
	void *pool;
	size_t pool_size;
};

int b1_client_new_from_fd(struct b1_client **out, int fd)
{
	struct b1_client *client;

	assert(out);
	assert(fd >= 0);

	client = malloc(sizeof(*client));
	if (!client)
		return -ENOMEM;

	client->fd = fd;
	client->pool = MAP_FAILED;

	*out = client;
	return 0;
}

int b1_client_new_from_path(struct b1_client **out, const char *path)
{
	int r, fd;

	if (!path)
		path = "/sys/fs/bus1/bus";

	fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	r = b1_client_new_from_fd(out, fd);
	if (r < 0)
		close(fd);

	return r;
}

int b1_client_new_from_mount(struct b1_client **out, const char *mount_path)
{
	char *path = NULL;
	size_t length;

	if (mount_path) {
		length = strlen(mount_path);
		if (length > PATH_MAX)
			return -ENAMETOOLONG;

		path = alloca(length + 5);
		memcpy(path, mount_path, length);
		memcpy(path + length, "/bus", 5);
	}

	return b1_client_new_from_path(out, path);
}

struct b1_client *b1_client_free(struct b1_client *client)
{
	if (!client)
		return client;

	if (client->pool != MAP_FAILED)
		munmap(client->pool, client->pool_size);
	if (client->fd >= 0)
		close(client->fd);
	free(client);

	return NULL;
}

int b1_client_resolve(struct b1_client *client, uint64_t *out_id, const char *name)
{
	struct bus1_cmd_resolve *cmd;
	size_t namelen;
	int r;

	assert(client);
	assert(name);

	namelen = strlen(name) + 1;
	if (namelen > BUS1_NAME_MAX_SIZE)
		return -EMSGSIZE;

	cmd = alloca(sizeof(*cmd) + namelen);
	cmd->size = sizeof(*cmd) + namelen;
	cmd->flags = 0;
	cmd->unique_id = 0;
	memcpy(cmd->name, name, namelen);

	r = ioctl(client->fd, BUS1_CMD_RESOLVE, &cmd);
	if (r < 0)
		return -errno;

	if (out_id)
		*out_id = cmd->unique_id;
	return 0;
}
