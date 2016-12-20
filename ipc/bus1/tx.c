/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include "peer.h"
#include "tx.h"
#include "util/active.h"
#include "util/queue.h"

static void bus1_tx_push(struct bus1_tx *tx,
			 struct bus1_queue_node **list,
			 struct bus1_queue_node *qnode)
{
	struct bus1_peer *peer = qnode->owner;

	/*
	 * Push @qnode onto one of the lists in @tx (specified as @list). Note
	 * that each list has different locking/ordering requirements, which
	 * the caller has to verify. This helper does not check them.
	 *
	 * Whenever something is pushed on a list, we make sure it has the tx
	 * set as group. Furthermore, we tell lockdep that its peer was
	 * released. This is required to allow holding hundreds of peers in a
	 * multicast without exceeding the lockdep limits of allowed locks held
	 * in parallel.
	 * Note that pushing a qnode on a list consumes the qnode together with
	 * its set owner. The caller must not access it, except by popping it
	 * from the list or using one of the internal list-iterators. In other
	 * words, we say that a caller must be aware of lockdep limitations
	 * whenever they hold an unlimited number of peers. However, if they
	 * make sure they only ever hold a fixed number, but use transaction
	 * lists to stash them, the transaction lists make sure to properly
	 * avoid lockdep limitations.
	 */

	WARN_ON(qnode->group && tx != qnode->group);
	WARN_ON(qnode->next || qnode == *list);

	qnode->group = tx;
	qnode->next = *list;
	*list = qnode;

	if (peer)
		bus1_active_lockdep_released(&peer->active);
}

static struct bus1_queue_node *
bus1_tx_pop(struct bus1_tx *tx, struct bus1_queue_node **list)
{
	struct bus1_queue_node *qnode = *list;
	struct bus1_peer *peer;

	/*
	 * This pops the first entry off a list on a transaction. Different
	 * lists have different locking requirements. This helper does not
	 * validate the context.
	 *
	 * Note that we need to tell lockdep about the acquired peer when
	 * returning the qnode. See bus1_tx_push() for details.
	 */

	if (qnode) {
		*list = qnode->next;
		qnode->next = NULL;
		peer = qnode->owner;
		if (peer)
			bus1_active_lockdep_acquired(&peer->active);
	}

	return qnode;
}

/*
 * This starts an iterator for a singly-linked list with head-elements given as
 * @list. @iter is filled with the first element, and its *acquired* peer is
 * returned. You *must* call bus1_tx_next() on @iter, otherwise you will run
 * into lockdep-ref-leaks. IOW: don't bail out of your loop with 'break'.
 *
 * It is supposed to be used like this:
 *
 *     for (peer = bus1_tx_first(tx, &tx->foo, &qnode);
 *          qnode;
 *          peer = bus1_tx_next(tx, &qnode))
 *             bar();
 */
static struct bus1_peer *bus1_tx_first(struct bus1_tx *tx,
				       struct bus1_queue_node *list,
				       struct bus1_queue_node **iter)
{
	struct bus1_peer *peer;

	if ((*iter = list)) {
		peer = list->owner;
		if (!peer)
			return tx->origin;

		bus1_active_lockdep_acquired(&peer->active);
		return peer;
	}

	return NULL;
}

/*
 * This continues an iteration of a singly-linked list started via
 * bus1_tx_first(). It returns the same information (see it for details).
 */
static struct bus1_peer *bus1_tx_next(struct bus1_tx *tx,
				      struct bus1_queue_node **iter)
{
	struct bus1_queue_node *qnode = *iter;
	struct bus1_peer *peer = qnode->owner;

	if (peer)
		bus1_active_lockdep_released(&peer->active);

	return bus1_tx_first(tx, qnode->next, iter);
}

static void bus1_tx_stage(struct bus1_tx *tx,
			  struct bus1_queue_node *qnode,
			  struct bus1_queue_node **list,
			  u64 *timestamp)
{
	struct bus1_peer *peer = qnode->owner ?: tx->origin;

	WARN_ON(test_bit(BUS1_TX_BIT_SEALED, &tx->flags));
	WARN_ON(bus1_queue_node_is_queued(qnode));
	lockdep_assert_held(&peer->data.lock);

	bus1_tx_push(tx, list, qnode);
	*timestamp = bus1_queue_stage(&peer->data.queue, qnode, *timestamp);
}

/**
 * bus1_tx_stage_sync() - stage message
 * @tx:				transaction to operate on
 * @qnode:			message to stage
 *
 * This stages @qnode on the transaction @tx. It is an error to call this on a
 * qnode that is already staged. The caller must set qnode->owner to the
 * destination peer and acquire it. If it is NULL, it is assumed to be the same
 * as the origin of the transaction.
 *
 * The caller must hold the data-lock of the destination peer.
 *
 * This consumes @qnode. The caller must increment the required reference
 * counts to make sure @qnode does not vanish.
 */
void bus1_tx_stage_sync(struct bus1_tx *tx, struct bus1_queue_node *qnode)
{
	bus1_tx_stage(tx, qnode, &tx->sync, &tx->timestamp);
}

/**
 * bus1_tx_stage_later() - postpone message
 * @tx:				transaction to operate on
 * @qnode:			message to postpone
 *
 * This queues @qnode on @tx, but does not stage it. It will be staged just
 * before the transaction is committed. This can be used over
 * bus1_tx_stage_sync() if no immediate staging is necessary, or if required
 * locks cannot be taken.
 *
 * It is a caller-error if @qnode is already part of a transaction.
 */
void bus1_tx_stage_later(struct bus1_tx *tx, struct bus1_queue_node *qnode)
{
	bus1_tx_push(tx, &tx->postponed, qnode);
}

/**
 * bus1_tx_join() - HIC SUNT DRACONES!
 * @whom:		whom to join
 * @qnode:		who joins
 *
 * This makes @qnode join the on-going transaction of @whom. That is, it is
 * semantically equivalent of calling:
 *
 *     bus1_tx_stage_sync(whom->group, qnode);
 *
 * However, you can only dereference whom->group while it is still ongoing.
 * Once committed, it might be a stale pointer. This function safely checks for
 * the required conditions and bails out if too late.
 *
 * The caller must hold the data locks of both peers (target of @whom and
 * @qnode). @node->owner must not be NULL! Furthermore, @qnode must not be
 * staged into any transaction, yet.
 *
 * In general, this function is not what you want. There is no guarantee that
 * you can join the transaction, hence a negative return value must be expected
 * by the caller and handled gracefully. In that case, this function guarantees
 * that the clock of the holder of @qnode is synced with the transaction of
 * @whom, and as such is correctly ordered against the transaction.
 *
 * If this function returns "false", you must settle on the transaction before
 * visibly reacting to it. That is, user-space must not see that you failed to
 * join the transaction before the transaction is settled!
 *
 * Return: True if successful, false if too late.
 */
bool bus1_tx_join(struct bus1_queue_node *whom, struct bus1_queue_node *qnode)
{
	struct bus1_peer *peer = qnode->owner;
	struct bus1_tx *tx;
	u64 timestamp;

	WARN_ON(!peer);
	WARN_ON(qnode->group);
	lockdep_assert_held(&peer->data.lock);

	if (bus1_queue_node_is_staging(whom)) {
		/*
		 * The anchor we want to join is marked as staging. We know its
		 * holder is locked by the caller, hence we know that its
		 * transaction must still be ongoing and at some point commit
		 * @whom (blocking on the lock we currently hold). This means,
		 * we are allowed to dereference @whom->group safely.
		 * Now, if the transaction has not yet acquired a commit
		 * timestamp, we simply stage @qnode and asynchronously join
		 * the transaction. But if the transaction is already sealed,
		 * we cannot join anymore. Hence, we instead copy the timestamp
		 * for our fallback.
		 */
		WARN_ON(!(tx = whom->group));
		lockdep_assert_held(&tx->origin->data.lock);

		if (!test_bit(BUS1_TX_BIT_SEALED, &tx->flags)) {
			bus1_tx_stage(tx, qnode, &tx->async, &tx->async_ts);
			return true;
		}

		timestamp = tx->timestamp;
	} else {
		/*
		 * The anchor to join is not marked as staging, hence we cannot
		 * dereference its transaction (the stack-frame might be gone
		 * already). Instead, we just copy the timestamp and try our
		 * fallback below.
		 */
		timestamp = bus1_queue_node_get_timestamp(whom);
	}

	/*
	 * The transaction of @whom has already acquired a commit timestamp.
	 * Hence, we cannot join the transaction. However, we can try to inject
	 * a synthetic entry into the queue of @peer. All we must make sure is
	 * that there is at least one entry ordered in front of it. Hence, we
	 * use bus1_queue_commit_synthetic(). If this synthetic entry would be
	 * the new front, the commit fails. This is, because we cannot know
	 * whether this peer already dequeued something to-be-ordered after
	 * this fake entry.
	 * In the case that the insertion fails, we make sure to have synced
	 * its clock before. This guarantees that any further actions of this
	 * peer are guaranteed to be ordered after the transaction to join.
	 */
	qnode->group = whom->group;
	bus1_queue_sync(&peer->data.queue, timestamp);
	return bus1_queue_commit_synthetic(&peer->data.queue, qnode, timestamp);
}

/**
 * bus1_tx_commit() - commit transaction
 * @tx:				transaction to operate on
 *
 * Commit a transaction. First all postponed entries are staged, then we commit
 * all messages that belong to this transaction. This works with any number of
 * messages.
 *
 * Return: This returns the commit timestamp used.
 */
u64 bus1_tx_commit(struct bus1_tx *tx)
{
	struct bus1_queue_node *qnode, **tail;
	struct bus1_peer *peer, *origin = tx->origin;

	if (WARN_ON(test_bit(BUS1_TX_BIT_SEALED, &tx->flags)))
		return tx->timestamp;

	/*
	 * Stage Round
	 * Callers can stage messages manually via bus1_tx_stage_*(). However,
	 * if they cannot lock the destination queue for whatever reason, we
	 * support postponing it. In that case, it is linked into tx->postponed
	 * and we stage it here for them.
	 */
	while ((qnode = bus1_tx_pop(tx, &tx->postponed))) {
		peer = qnode->owner ?: tx->origin;

		mutex_lock(&peer->data.lock);
		bus1_tx_stage_sync(tx, qnode);
		mutex_unlock(&peer->data.lock);
	}

	/*
	 * Acquire Commit TS
	 * Now that everything is staged, we atomically acquire a commit
	 * timestamp from the transaction origin. We store it on the
	 * transaction, so async joins are still possible. We also seal the
	 * transaction at the same time, to prevent async stages.
	 */
	mutex_lock(&origin->data.lock);
	bus1_queue_sync(&origin->data.queue, max(tx->timestamp, tx->async_ts));
	tx->timestamp = bus1_queue_tick(&origin->data.queue);
	WARN_ON(test_and_set_bit(BUS1_TX_BIT_SEALED, &tx->flags));
	mutex_unlock(&origin->data.lock);

	/*
	 * Sync Round
	 * Before any effect of this transaction is visible, we must make sure
	 * to sync all clocks. This guarantees that the first receiver of the
	 * message cannot (via side-channels) induce messages into the queue of
	 * the other receivers, before they get the message as well.
	 */
	tail = &tx->sync;
	do {
		for (peer = bus1_tx_first(tx, *tail, &qnode);
		     qnode;
		     peer = bus1_tx_next(tx, &qnode)) {
			tail = &qnode->next;

			mutex_lock(&peer->data.lock);
			bus1_queue_sync(&peer->data.queue, tx->timestamp);
			mutex_unlock(&peer->data.lock);
		}

		/* append async-list to the tail of the previous list */
		*tail = tx->async;
		tx->async = NULL;
	} while (*tail);

	/*
	 * Commit Round
	 * Now that everything is staged and the clocks synced, we can finally
	 * commit all the messages on their respective queues. Iterate over
	 * each message again, commit it, and release the pinned destination.
	 */
	while ((qnode = bus1_tx_pop(tx, &tx->sync))) {
		peer = qnode->owner ?: tx->origin;

		mutex_lock(&peer->data.lock);
		bus1_queue_commit_staged(&peer->data.queue, &peer->waitq,
					 qnode, tx->timestamp);
		mutex_unlock(&peer->data.lock);

		bus1_peer_release(qnode->owner);
	}

	return tx->timestamp;
}
