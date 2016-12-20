#ifndef __BUS1_TX_H
#define __BUS1_TX_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Transactions
 *
 * The transaction engine is an object that lives on the stack and is used to
 * stage and commit multicasts properly. Unlike unicasts, a multicast cannot
 * just be queued on each destination, but must be properly synchronized. This
 * requires us to first stage each message on their respective destination,
 * then sync and tick the clocks, and eventual commit all messages.
 */

#include <linux/err.h>
#include <linux/kernel.h>

struct bus1_peer;
struct bus1_queue_node;

/**
 * enum bus1_tx_bits - transaction flags
 * @BUS1_TX_BIT_SEALED:		The transaction is sealed, no new messages can
 *				be added to the transaction. The commit of all
 *				staged messages is ongoing.
 */
enum bus1_tx_bits {
	BUS1_TX_BIT_SEALED,
};

/**
 * struct bus1_tx - transaction context
 * @origin:			origin of this transaction
 * @sync:			unlocked list of staged messages
 * @async:			locked list of staged messages
 * @postponed:			unlocked list of unstaged messages
 * @flags:			transaction flags
 * @timestamp:			unlocked timestamp of this transaction
 * @async_ts:			locked timestamp cache of async list
 */
struct bus1_tx {
	struct bus1_peer *origin;
	struct bus1_queue_node *sync;
	struct bus1_queue_node *async;
	struct bus1_queue_node *postponed;
	unsigned long flags;
	u64 timestamp;
	u64 async_ts;
};

void bus1_tx_stage_sync(struct bus1_tx *tx, struct bus1_queue_node *qnode);
void bus1_tx_stage_later(struct bus1_tx *tx, struct bus1_queue_node *qnode);

bool bus1_tx_join(struct bus1_queue_node *whom, struct bus1_queue_node *qnode);

u64 bus1_tx_commit(struct bus1_tx *tx);

/**
 * bus1_tx_init() - initialize transaction context
 * @tx:				transaction context to operate on
 * @origin:			origin of this transaction
 *
 * This initializes a transaction context. The initiating peer must be pinned
 * by the caller for the entire lifetime of @tx (until bus1_tx_deinit() is
 * called) and given as @origin.
 */
static inline void bus1_tx_init(struct bus1_tx *tx, struct bus1_peer *origin)
{
	tx->origin = origin;
	tx->sync = NULL;
	tx->async = NULL;
	tx->postponed = NULL;
	tx->flags = 0;
	tx->timestamp = 0;
	tx->async_ts = 0;
}

/**
 * bus1_tx_deinit() - deinitialize transaction context
 * @tx:				transaction context to operate on
 *
 * This deinitializes a transaction context previously created via
 * bus1_tx_init(). This is merely for debugging, as no resources are pinned on
 * the transaction. However, if any message was staged on the transaction, it
 * must be committed via bus1_tx_commit() before it is deinitialized.
 */
static inline void bus1_tx_deinit(struct bus1_tx *tx)
{
	WARN_ON(tx->sync);
	WARN_ON(tx->async);
	WARN_ON(tx->postponed);
}

#endif /* __BUS1_TX_H */
