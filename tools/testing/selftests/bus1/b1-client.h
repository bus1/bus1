#ifndef __B1_CLIENT_H
#define __B1_CLIENT_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Bus1 Client API
 *
 * XXX
 */

#include <inttypes.h>
#include <linux/bus1.h>

struct b1_client;

int b1_client_new_from_fd(struct b1_client **out, int fd);
int b1_client_new_from_path(struct b1_client **out, const char *path);
int b1_client_new_from_mount(struct b1_client **out, const char *mount_path);
struct b1_client *b1_client_free(struct b1_client *client);

int b1_client_resolve(struct b1_client *client, uint64_t *out_id, const char *name);

int b1_client_connect(struct b1_client *client, const char **names, size_t n_names);
int b1_client_disconnect(struct b1_client *client);

int b1_client_track(struct b1_client *client, uint64_t id);
int b1_client_untrack(struct b1_client *client, uint64_t id);

int b1_client_send(struct b1_client *client, ...);
int b1_client_recv(struct b1_client *client, ...);

#endif /* __B1_CLIENT_H */
