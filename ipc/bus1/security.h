#ifndef __BUS1_SECURITY_H
#define __BUS1_SECURITY_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Security
 *
 * This implements LSM hooks for bus1. Out-of-tree modules cannot provide their
 * own hooks, so we just provide stubs that are to be converted into real LSM
 * hooks once this is no longer out-of-tree.
 */

struct bus1_handle;
struct bus1_peer;
struct file;

static inline int security_bus1_transfer_message(struct bus1_peer *from,
						 struct bus1_peer *to)
{
	return 0;
}

static inline int security_bus1_transfer_handle(struct bus1_peer *from,
						struct bus1_peer *to,
						struct bus1_handle *node)
{
	return 0;
}

static inline int security_bus1_transfer_file(struct bus1_peer *from,
					      struct bus1_peer *to,
					      struct file *what)
{
	return 0;
}

#endif /* __BUS1_SECURITY_H */
