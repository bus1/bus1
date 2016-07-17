/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include "test.h"

static int multicast_handles(struct bus1_client *client,
			     const uint64_t *destinations,
			     size_t n_destinations,
			     const uint64_t *handles,
			     size_t n_handles)
{
	struct bus1_cmd_send send = {
		.ptr_destinations = (uintptr_t)destinations,
		.n_destinations = n_destinations,
		.ptr_handles = (uintptr_t)handles,
		.n_handles = n_handles,
	};

	return bus1_client_send(client, &send);
}

/* verify behavior of transferring existing and new handles via multicast */
static void test_xfer_multicast(void)
{
	struct bus1_cmd_recv recv;
	struct bus1_client *c1, *c2, *c3;
	uint64_t node2, node3, node20, node30;
	uint64_t handle2, handle3, handle20, handle30;
	uint64_t array_dest[2], array_handles[6];
	const uint64_t *p;
	const uint8_t *slice;
	int r, fd;

	/*
	 * We create a root peer @c1 with 2 nodes, each of which is imported
	 * into one clone each. We now create a node in each clone and send a
	 * handle back to @c1. Those nodes are called @node20 and @node30. Once
	 * done, we multicast from @c1 to those new nodes, thus reaching the
	 * queues of @c2 and @c3. This multicast carries all so far known
	 * handles, and also allocates new nodes on-the-fly. Finally, we verify
	 * each client got what we expected.
	 */

	/* create new peer and two clones */

	r = bus1_client_new_from_path(&c1, test_path);
	assert(r >= 0);
	r = bus1_client_init(c1, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);
	r = bus1_client_mmap(c1);
	assert(r >= 0);

	node2 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle2 = BUS1_HANDLE_INVALID;
	fd = -1;
	r = bus1_client_clone(c1, &node2, &handle2, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);
	r = bus1_client_new_from_fd(&c2, fd);
	assert(r >= 0);
	r = bus1_client_mmap(c2);
	assert(r >= 0);

	node3 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle3 = BUS1_HANDLE_INVALID;
	fd = -1;
	r = bus1_client_clone(c1, &node3, &handle3, &fd, BUS1_CLIENT_POOL_SIZE);
	assert(r >= 0);
	r = bus1_client_new_from_fd(&c3, fd);
	assert(r >= 0);
	r = bus1_client_mmap(c3);
	assert(r >= 0);

	/* create node20 by sending back to c1 */

	node20 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = multicast_handles(c2, &handle2, 1, &node20, 1);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.data.n_handles == 1);
	assert(recv.data.n_fds == 0);

	slice = bus1_client_slice_from_offset(c1, recv.data.offset);
	handle20 = *(uint64_t *)(slice + c_align_to(recv.data.n_bytes, 8));
	assert(!(handle20 & BUS1_NODE_FLAG_ALLOCATE));
	assert(handle20 & BUS1_NODE_FLAG_MANAGED);

	/* create node30 by sending back to c1 */

	node30 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = multicast_handles(c3, &handle3, 1, &node30, 1);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.data.n_handles == 1);
	assert(recv.data.n_fds == 0);

	slice = bus1_client_slice_from_offset(c1, recv.data.offset);
	handle30 = *(uint64_t *)(slice + c_align_to(recv.data.n_bytes, 8));
	assert(!(handle30 & BUS1_NODE_FLAG_ALLOCATE));
	assert(handle30 & BUS1_NODE_FLAG_MANAGED);

	/* multicast everything to c2 and c3 */

	array_dest[0] = handle20;
	array_dest[1] = handle30;
	array_handles[0] = handle20;
	array_handles[1] = handle30;
	array_handles[2] = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	array_handles[3] = node2;
	array_handles[4] = node3;
	array_handles[5] = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = multicast_handles(c1, array_dest, 2, array_handles, 6);
	assert(r >= 0);

	/* dequeue on c2 and verify content */

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(c2, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.data.n_handles == 6);
	assert(recv.data.n_fds == 0);

	slice = bus1_client_slice_from_offset(c2, recv.data.offset);

	p = (uint64_t *)(slice + c_align_to(recv.data.n_bytes, 8));
	assert(*p == node20);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(*p == handle2);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	/* dequeue on c3 and verify content */

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(c3, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.data.n_handles == 6);
	assert(recv.data.n_fds == 0);

	slice = bus1_client_slice_from_offset(c3, recv.data.offset);

	p = (uint64_t *)(slice + c_align_to(recv.data.n_bytes, 8));
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(*p == node30);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	++p;
	assert(*p == handle3);

	++p;
	assert(!(*p & BUS1_NODE_FLAG_ALLOCATE));
	assert(*p & BUS1_NODE_FLAG_MANAGED);

	/* verify that all queues are empty */

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(c1, &recv);
	assert(r == -EAGAIN);
	r = bus1_client_recv(c2, &recv);
	assert(r == -EAGAIN);
	r = bus1_client_recv(c3, &recv);
	assert(r == -EAGAIN);

	/*
	 * By destroying/releasing the resources, verify that c1 has:
	 *  - 1x node2
	 *  - 1x node3
	 *  - 1x handle20
	 *  - 1x handle30
	 */

	r = bus1_client_node_destroy(c1, node2);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, node2);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, node2);
	assert(r < 0);

	r = bus1_client_node_destroy(c1, node3);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, node3);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, node3);
	assert(r < 0);

	r = bus1_client_node_destroy(c1, handle20);
	assert(r < 0);
	r = bus1_client_handle_release(c1, handle20);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, handle20);
	assert(r < 0);

	r = bus1_client_node_destroy(c1, handle30);
	assert(r < 0);
	r = bus1_client_handle_release(c1, handle30);
	assert(r >= 0);
	r = bus1_client_handle_release(c1, handle30);
	assert(r < 0);

	/*
	 * ..and c2 owns:
	 *  - 2x handle2
	 *  - 2x node20
	 */

	r = bus1_client_node_destroy(c2, handle2);
	assert(r < 0);
	r = bus1_client_handle_release(c2, handle2);
	assert(r >= 0);
	r = bus1_client_handle_release(c2, handle2);
	assert(r >= 0);
	r = bus1_client_handle_release(c2, handle2);
	assert(r < 0);

	r = bus1_client_node_destroy(c2, node20);
	assert(r >= 0);
	r = bus1_client_handle_release(c2, node20);
	assert(r >= 0);
	r = bus1_client_handle_release(c2, node20);
	assert(r >= 0);
	r = bus1_client_handle_release(c2, node20);
	assert(r < 0);

	/*
	 * ..and c3 owns:
	 *  - 2x handle3
	 *  - 2x node30
	 */

	r = bus1_client_node_destroy(c3, handle3);
	assert(r < 0);
	r = bus1_client_handle_release(c3, handle3);
	assert(r >= 0);
	r = bus1_client_handle_release(c3, handle3);
	assert(r >= 0);
	r = bus1_client_handle_release(c3, handle3);
	assert(r < 0);

	r = bus1_client_node_destroy(c3, node30);
	assert(r >= 0);
	r = bus1_client_handle_release(c3, node30);
	assert(r >= 0);
	r = bus1_client_handle_release(c3, node30);
	assert(r >= 0);
	r = bus1_client_handle_release(c3, node30);
	assert(r < 0);

	/*
	 * Drop peers. There are foreign handles left (e.g., copy of handle3 in
	 * c2), but their IDs are random as they've been allocated in a
	 * different ID space. We don't verify their correctness here, but just
	 * drop them silently by releasing the peers (same is true for the
	 * notifications that have been queued).
	 */

	bus1_client_free(c3);
	bus1_client_free(c2);
	bus1_client_free(c1);
}

int test_xfer(void)
{
	test_xfer_multicast();
	return TEST_OK;
}
