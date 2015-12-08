#ifndef __BUS1_PEER_H
#define __BUS1_PEER_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Peers
 *
 * XXX
 */

struct bus1_peer {
	int unused;
};

struct bus1_peer *bus1_peer_new(void);
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer);

#endif /* __BUS1_PEER_H */
