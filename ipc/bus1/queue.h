#ifndef __BUS1_QUEUE_H
#define __BUS1_QUEUE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Message Queue
 *
 * XXX
 */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>

struct bus1_pool_slice;

/**
 * struct bus1_queue_entry - queue entry
 * @entry:	link into the queue
 * @slice:	carried data, or NULL
 * @n_files:	number of carried files
 * @files:	carried files, or NULL
 */
struct bus1_queue_entry {
	struct list_head entry;
	struct bus1_pool_slice *slice;
	size_t n_files;
	struct file *files[0];
};

/**
 * struct bus1_queue - message queue
 * @messages:	list of linked messages
 */
struct bus1_queue {
	struct list_head messages;
};

void bus1_queue_init(struct bus1_queue *queue);
void bus1_queue_destroy(struct bus1_queue *queue);
struct bus1_queue_entry *bus1_queue_peek(struct bus1_queue *queue);
void bus1_queue_push(struct bus1_queue *queue, struct bus1_queue_entry *entry);
struct bus1_queue_entry *bus1_queue_pop(struct bus1_queue *queue);

struct bus1_queue_entry *bus1_queue_entry_new(size_t n_files);
struct bus1_queue_entry *bus1_queue_entry_free(struct bus1_queue_entry *entry);
int bus1_queue_entry_install(struct bus1_queue_entry *entry,
			     struct bus1_pool *pool);

#endif /* __BUS1_QUEUE_H */
