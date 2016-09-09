/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include "test.h"

static int multicast_handles(struct bus1_peer *client,
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

	return bus1_peer_send(client, &send);
}

/* verify behavior of transferring existing and new handles via multicast */
static void test_xfer_multicast(void)
{
	struct bus1_cmd_recv recv;
	struct bus1_peer *c1, *c2, *c3;
	uint64_t node2, node3, node20, node30;
	uint64_t handle2, handle3, handle20, handle30;
	uint64_t array_dest[2], array_handles[6], array_nodes[2];
	struct bus1_cmd_node_destroy destroy = {
		.ptr_nodes = (uintptr_t)array_nodes,
	};
	const uint64_t *p;
	const uint8_t *slice;
	int r;

	/*
	 * We create three peers @c1, @c2 and @c3. @c1 has two nodes, each of
	 * which is imported into one of the two other peers. We now create a
	 * node in each child peer and send a handle back to @c1. Those nodes
	 * are called @node20 and @node30. Once done, we multicast from @c1 to
	 * those new nodes, thus reaching the queues of @c2 and @c3. This
	 * multicast carries all so far known handles, and also allocates new
	 * nodes on-the-fly. Finally, we verify each client got what we
	 * expected.
	 */

	/*
	 * Create three peers and pass a handle from the second and third
	 * to the first.
	 */

	r = bus1_peer_new_from_path(&c1, test_path);
	assert(r >= 0);
	r = bus1_peer_mmap(c1);
	assert(r >= 0);
	r = bus1_peer_new_from_path(&c2, test_path);
	assert(r >= 0);
	r = bus1_peer_mmap(c2);
	assert(r >= 0);
	r = bus1_peer_new_from_path(&c3, test_path);
	assert(r >= 0);
	r = bus1_peer_mmap(c3);
	assert(r >= 0);

	node2 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle2 = BUS1_HANDLE_INVALID;
	r = bus1_peer_handle_transfer(c1, c2, &node2, &handle2);
	assert(r >= 0);

	node3 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle3 = BUS1_HANDLE_INVALID;
	r = bus1_peer_handle_transfer(c1, c3, &node3, &handle3);
	assert(r >= 0);

	/* create node20 by sending back to c1 */

	node20 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = multicast_handles(c2, &handle2, 1, &node20, 1);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_DATA);
	assert(recv.msg.n_handles == 1);
	assert(recv.msg.n_fds == 0);

	slice = bus1_peer_slice_from_offset(c1, recv.msg.offset);
	handle20 = *(uint64_t *)(slice + c_align_to(recv.msg.n_bytes, 8));
	assert(!(handle20 & BUS1_NODE_FLAG_ALLOCATE));
	assert(handle20 & BUS1_NODE_FLAG_MANAGED);

	/* create node30 by sending back to c1 */

	node30 = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = multicast_handles(c3, &handle3, 1, &node30, 1);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_DATA);
	assert(recv.msg.n_handles == 1);
	assert(recv.msg.n_fds == 0);

	slice = bus1_peer_slice_from_offset(c1, recv.msg.offset);
	handle30 = *(uint64_t *)(slice + c_align_to(recv.msg.n_bytes, 8));
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
	r = bus1_peer_recv(c2, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_DATA);
	assert(recv.msg.n_handles == 6);
	assert(recv.msg.n_fds == 0);

	slice = bus1_peer_slice_from_offset(c2, recv.msg.offset);

	p = (uint64_t *)(slice + c_align_to(recv.msg.n_bytes, 8));
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
	r = bus1_peer_recv(c3, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_DATA);
	assert(recv.msg.n_handles == 6);
	assert(recv.msg.n_fds == 0);

	slice = bus1_peer_slice_from_offset(c3, recv.msg.offset);

	p = (uint64_t *)(slice + c_align_to(recv.msg.n_bytes, 8));
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
	r = bus1_peer_recv(c1, &recv);
	assert(r == -EAGAIN);
	r = bus1_peer_recv(c2, &recv);
	assert(r == -EAGAIN);
	r = bus1_peer_recv(c3, &recv);
	assert(r == -EAGAIN);

	/*
	 * By destroying/releasing the resources, verify that c1 has:
	 *  - 1x node2
	 *  - 1x node3
	 *  - 1x handle20
	 *  - 1x handle30
	 */

	array_nodes[0] = node2;
	array_nodes[1] = node3;
	destroy.n_nodes = 2;

	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r >= 0);
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c1, node2);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c1, node3);
	assert(r < 0);
	assert(r == -ENXIO);

	destroy.n_nodes = 1;

	array_nodes[0] = handle20;
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c1, handle20);
	assert(r >= 0);
	r = bus1_peer_handle_release(c1, handle20);
	assert(r < 0);
	assert(r == -ENXIO);

	array_nodes[0] = handle30;
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c1, handle30);
	assert(r >= 0);
	r = bus1_peer_handle_release(c1, handle30);
	assert(r < 0);
	assert(r == -ENXIO);

	/*
	 * ..and c2 owns:
	 *  - 2x handle2
	 *  - 1x node20
	 */

	array_nodes[0] = handle2;
	r = bus1_peer_node_destroy(c2, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c2, handle2);
	assert(r >= 0);
	r = bus1_peer_handle_release(c2, handle2);
	assert(r >= 0);
	r = bus1_peer_handle_release(c2, handle2);
	assert(r < 0);
	assert(r == -ENXIO);

	array_nodes[0] = node20;
	r = bus1_peer_node_destroy(c2, &destroy);
	assert(r >= 0);
	r = bus1_peer_node_destroy(c2, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c2, node20);
	assert(r >= 0);
	r = bus1_peer_handle_release(c2, node20);
	assert(r < 0);
	assert(r == -ENXIO);

	/*
	 * ..and c3 owns:
	 *  - 2x handle3
	 *  - 1x node30
	 */

	array_nodes[0] = handle3;
	r = bus1_peer_node_destroy(c3, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c3, handle3);
	assert(r >= 0);
	r = bus1_peer_handle_release(c3, handle3);
	assert(r >= 0);
	r = bus1_peer_handle_release(c3, handle3);
	assert(r < 0);
	assert(r == -ENXIO);

	array_nodes[0] = node30;
	r = bus1_peer_node_destroy(c3, &destroy);
	assert(r >= 0);
	r = bus1_peer_node_destroy(c3, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c3, node30);
	assert(r >= 0);
	r = bus1_peer_handle_release(c3, node30);
	assert(r < 0);
	assert(r == -ENXIO);

	/*
	 * Drop peers. There are foreign handles left (e.g., copy of handle3 in
	 * c2), but their IDs are random as they've been allocated in a
	 * different ID space. We don't verify their correctness here, but just
	 * drop them silently by releasing the peers (same is true for the
	 * notifications that have been queued).
	 */

	bus1_peer_free(c3);
	bus1_peer_free(c2);
	bus1_peer_free(c1);
}

static void test_xfer_release_notification(void)
{
	struct bus1_cmd_recv recv;
	struct bus1_cmd_node_destroy destroy;
	struct bus1_peer *c1, *c2;
	uint64_t node, handle;
	int r;

	r = bus1_peer_new_from_path(&c1, test_path);
	assert(r >= 0);
	r = bus1_peer_new_from_path(&c2, test_path);
	assert(r >= 0);

	node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle = BUS1_HANDLE_INVALID;
	r = bus1_peer_handle_transfer(c1, c2, &node, &handle);
	assert(r >= 0);

	r = bus1_peer_handle_release(c2, handle);
	assert(r >= 0);
	r = bus1_peer_handle_release(c2, handle);
	assert(r < 0);
	assert(r == -ENXIO);
	r = bus1_peer_handle_release(c1, node);
	assert(r < 0);
	assert(r == -ENXIO);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(recv.msg.destination == node);

	destroy = (struct bus1_cmd_node_destroy){
		.ptr_nodes = (uintptr_t)&node,
		.n_nodes = 1,
	};
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(recv.msg.destination == node);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r < 0);
	assert(r == -EAGAIN);
	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c2, &recv);
	assert(r < 0);
	assert(r == -EAGAIN);

	bus1_peer_free(c2);
	bus1_peer_free(c1);
}

static void test_xfer_destroy_notification(void)
{
	struct bus1_cmd_recv recv;
	struct bus1_peer *c1, *c2;
	uint64_t node, handle;
	struct bus1_cmd_node_destroy destroy = {
		.ptr_nodes = (uintptr_t)&node,
		.n_nodes = 1,
	};
	int r;

	r = bus1_peer_new_from_path(&c1, test_path);
	assert(r >= 0);
	r = bus1_peer_new_from_path(&c2, test_path);
	assert(r >= 0);

	node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	handle = BUS1_HANDLE_INVALID;
	r = bus1_peer_handle_transfer(c1, c2, &node, &handle);
	assert(r >= 0);

	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r >= 0);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c2, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(recv.msg.destination == handle);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(recv.msg.destination == node);

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r < 0);
	assert(r == -EAGAIN);
	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c2, &recv);
	assert(r < 0);
	assert(r == -EAGAIN);

	bus1_peer_free(c2);
	bus1_peer_free(c1);
}

int test_xfer(void)
{
	test_xfer_multicast();
	test_xfer_destroy_notification();
	test_xfer_release_notification();
	return TEST_OK;
}
