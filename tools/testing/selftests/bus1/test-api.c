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

/* make sure /dev/busX exists, is a cdev and accessible */
static void test_api_cdev(void)
{
	const uint8_t *map;
	struct stat st;
	size_t n_map;
	int r, fd;

	r = access(test_path, F_OK);
	assert(r >= 0);

	r = stat(test_path, &st);
	assert(r >= 0);
	assert((st.st_mode & S_IFMT) == S_IFCHR);

	r = open(test_path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	assert(r >= 0);
	close(r);

	fd = test_open(&map, &n_map);
	test_close(fd, map, n_map);
}

/* make sure basic connect works */
static void test_api_connect(void)
{
	struct bus1_cmd_peer_reset cmd_reset = {
		.flags			= 0,
		.peer_flags		= -1,
		.max_slices		= -1,
		.max_handles		= -1,
		.max_inflight_bytes	= -1,
		.max_inflight_fds	= -1,
	};
	const uint8_t *map1;
	size_t n_map1;
	int r, fd1;

	/* create @fd1 */

	fd1 = test_open(&map1, &n_map1);

	/* test empty RESET */

	r = bus1_ioctl_peer_reset(fd1, &cmd_reset);
	assert(r >= 0);

	/* test DISCONNECT and verify ESHUTDOWN afterwards */

	r = bus1_ioctl_peer_disconnect(fd1);
	assert(r >= 0);

	r = bus1_ioctl_peer_disconnect(fd1);
	assert(r < 0);
	assert(r == -ESHUTDOWN);

	r = bus1_ioctl_peer_reset(fd1, &cmd_reset);
	assert(r < 0);
	assert(r == -ESHUTDOWN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* make sure basic transfer works */
static void test_api_transfer(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	const uint8_t *map1, *map2;
	size_t n_map1, n_map2;
	int r, fd1, fd2;

	/* setup */

	fd1 = test_open(&map1, &n_map1);
	fd2 = test_open(&map2, &n_map2);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= 0x100,
		.dst_fd			= fd2,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle != BUS1_HANDLE_INVALID);
	assert(cmd_transfer.dst_handle & BUS1_HANDLE_FLAG_MANAGED);
	assert(cmd_transfer.dst_handle & BUS1_HANDLE_FLAG_REMOTE);

	/* cleanup */

	test_close(fd2, map2, n_map2);
	test_close(fd1, map1, n_map1);
}

/* test release notification */
static void test_api_notify_release(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	struct bus1_cmd_recv cmd_recv;
	const uint8_t *map1;
	uint64_t id = 0x100;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= id,
		.dst_fd			= -1,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle == id);

	/* no message can be queued */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* release handle to trigger release notification */

	r = bus1_ioctl_handle_release(fd1, &id);
	assert(r == 0);

	/* dequeue release notification */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	/* no more messages */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/*
	 * Trigger the same thing again.
	 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= id,
		.dst_fd			= -1,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle == id);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	r = bus1_ioctl_handle_release(fd1, &id);
	assert(r == 0);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* test destroy notification */
static void test_api_notify_destroy(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	struct bus1_cmd_nodes_destroy cmd_destroy;
	struct bus1_cmd_recv cmd_recv;
	uint64_t node = 0x100, handle;
	const uint8_t *map1, *map2;
	size_t n_map1, n_map2;
	int r, fd1, fd2;

	/* setup */

	fd1 = test_open(&map1, &n_map1);
	fd2 = test_open(&map2, &n_map2);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= node,
		.dst_fd			= fd2,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	handle = cmd_transfer.dst_handle;

	/* both queues must be empty */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map2,
	};
	r = bus1_ioctl_recv(fd2, &cmd_recv);
	assert(r == -EAGAIN);

	/* destroy node and trigger destruction notification */

	cmd_destroy = (struct bus1_cmd_nodes_destroy){
		.flags			= 0,
		.ptr_nodes		= (unsigned long)&node,
		.n_nodes		= 1,
	};
	r = bus1_ioctl_nodes_destroy(fd1, &cmd_destroy);
	assert(r >= 0);

	/* dequeue destruction notification */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == node);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd2, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == handle);

	/* cleanup */

	test_close(fd2, map2, n_map2);
	test_close(fd1, map1, n_map1);
}

/* make sure basic unicasts works */
static void test_api_unicast(void)
{
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	const uint8_t *map1;
	uint64_t id = 0x100;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* send empty message */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)&id,
		.ptr_errors		= 0,
		.n_destinations		= 1,
		.ptr_vecs		= 0,
		.n_vecs			= 0,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	/* retrieve empty message */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	/* queue must be empty now */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* make sure basic unicasts work across peers */
static void test_api_unicast_remote(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	uint64_t node = 0x100, handle;
	const uint8_t *map1, *map2;
	size_t n_map1, n_map2;
	int r, fd1, fd2;

	/* setup */

	fd1 = test_open(&map1, &n_map1);
	fd2 = test_open(&map2, &n_map2);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= node,
		.dst_fd			= fd2,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	handle = cmd_transfer.dst_handle;

	/* send empty message */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)&handle,
		.ptr_errors		= 0,
		.n_destinations		= 1,
		.ptr_vecs		= 0,
		.n_vecs			= 0,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd2, &cmd_send);
	assert(r >= 0);

	/* retrieve empty message */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == node);

	/* cleanup */

	test_close(fd2, map2, n_map2);
	test_close(fd1, map1, n_map1);
}

/* make sure basic multicasts works */
static void test_api_multicast(void)
{
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	uint64_t ids[] = { 0x100, 0x200 };
	uint64_t data[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
	struct iovec vec = { data, sizeof(data) };
	const uint8_t *map1;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* send multicast */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)ids,
		.ptr_errors		= 0,
		.n_destinations		= sizeof(ids) / sizeof(*ids),
		.ptr_vecs		= (unsigned long)&vec,
		.n_vecs			= 1,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	/* retrieve messages */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == BUS1_MSG_FLAG_CONTINUE);
	assert(cmd_recv.msg.destination == ids[0] ||
	       cmd_recv.msg.destination == ids[1]);
	assert(cmd_recv.msg.n_bytes == sizeof(data));
	assert(!memcmp(map1 + cmd_recv.msg.offset, data, sizeof(data)));

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == ids[0] ||
	       cmd_recv.msg.destination == ids[1]);
	assert(cmd_recv.msg.n_bytes == sizeof(data));
	assert(!memcmp(map1 + cmd_recv.msg.offset, data, sizeof(data)));

	/* queue must be empty now */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* make sure basic payload-handles work */
static void test_api_handle(void)
{
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	uint64_t id = 0x100;
	const uint8_t *map1;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* send message */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)&id,
		.ptr_errors		= 0,
		.n_destinations		= 1,
		.ptr_vecs		= 0,
		.n_vecs			= 0,
		.ptr_handles		= (unsigned long)&id,
		.n_handles		= 1,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	/* retrieve messages */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);
	assert(cmd_recv.msg.n_handles == 1);

	/* queue must be empty now */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* releasing one reference must trigger a release notification */

	r = bus1_ioctl_handle_release(fd1, &id);
	assert(r >= 0);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	/* queue must be empty again */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

int main(int argc, char **argv)
{
	int r;

	r = test_parse_argv(argc, argv);
	if (r > 0) {
		test_api_cdev();
		test_api_connect();
		test_api_transfer();
		test_api_notify_release();
		test_api_notify_destroy();
		test_api_unicast();
		test_api_unicast_remote();
		test_api_multicast();
		test_api_handle();
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
