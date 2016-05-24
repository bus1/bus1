#ifndef __BUS1_HANDLE_H
#define __BUS1_HANDLE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Handles
 *
 * The object system on a bus is based on nodes and handles. Any peer can
 * allocate new, local objects at any time. They automatically become the sole
 * owner of the object. Those objects can be passed as payload of messages. The
 * recipient will thus gain a reference to the object as well. Additionally, an
 * object can be the destination of a message, in which case the message is
 * always sent to the original creator (and thus the owner) of the object.
 *
 * Internally, objects are called 'nodes'. A reference to an object is a
 * 'handle'. Whenever a new node is created, the owner implicitly gains an
 * handle as well. In fact, handles are the only way to refer to a node. The
 * node itself is entirely hidden in the implementation.
 *
 * Whenever a handle is passed as payload of a message, the target peer will
 * gain a handle linked to the same underlying node. This works regardless
 * whether the sender is the owner of the underlying node, or not.
 *
 * Each peer can identify all its handles (both owned and un-owned) by a 64bit
 * integer. The namespace is local to each peer, and the numbers cannot be
 * compared with the numbers of other peers (in fact, they will be very likely
 * to clash, but might still have *different* underlying nodes). However, if a
 * peer receives a reference to the same node multiple times, the resulting
 * handle will be the same. The kernel keeps count how often each peer owns a
 * handle.
 *
 * If a peer no longer requires a specific handle, it must release it. If the
 * peer releases its last reference to a handle, the handle will be destroyed.
 *
 * The ID of an handle is (almost) never reused. That is, once a handle was
 * fully released, any new handle the peer receives will have a different ID.
 * The only scenario where an ID is reused, is if the peer gains a new handle
 * to an underlying node that it already owned a handle for earlier. This might
 * happen, for instance, if a message is inflight that carries a handle that
 * the peer was just about to release. Furthermore, the handle of the owner of
 * a node is internally pinned. As such, it is always reused if the owner gains
 * a handle to its own node again (this is required for explicit node
 * destruction).
 * Note that such ID-reuse is not guaranteed, though. If a peer used to own a
 * handle, dropped it and gains another one for the same underlying node, the
 * new ID might be completely different! The only guarantee here is: If the ID
 * is the same as a previously owned ID, then the underlying node is still the
 * same.
 *
 * Once all handles to a specific node have been released, the node is
 * unreferenced and is automatically destroyed. The owner of the node is
 * notified of this, so it can destroy any linked state. Note that the owner of
 * a node owns a handle themself, so it needs to release it as well to trigger
 * the destruction of the node.
 * Additionally, the owner of a node (and *only* the owner) can trigger
 * destruction of a node manually (even if other peers still own handles). In
 * this case, all peers that own a handle are notified by this.
 *
 * Node destruction is fully synchronized with any transaction. That is, a node
 * and all its handles are valid in every message that is transmitted *before*
 * the notification of its destruction. Furthermore, no message after this
 * notification will carry the ID of such a destructed node.
 * Note that message transactions are fully async. That is, there is no unique
 * point in time that a message is synchronized with another message. Hence,
 * whether a specific handle passed with a message is still valid or not,
 * cannot be predicted by the sender, but only by one of the receivers.
 */

#include <linux/kernel.h>
#include <linux/rbtree.h>

struct bus1_handle;
struct bus1_peer;
struct bus1_peer_info;
struct bus1_queue_node;

/**
 * struct bus1_handle_dest - destination context
 * @handle:		local destination handle
 * @raw_peer:		remote destination peer (raw active ref)
 * @idp:		user-memory to store allocated ID at
 */
struct bus1_handle_dest {
	struct bus1_handle *handle;
	struct bus1_peer *raw_peer;
	u64 __user *idp;
};

/**
 * BUS1_HANDLE_BATCH_SIZE - number of handles per set in a batch
 *
 * We need to support large handle transactions, bigger than any linear
 * allocation we're supposed to do in a running kernel. Hence, we batch all
 * handles in a transaction into sets of this size. The `bus1_handle_batch`
 * object transparently hides this, and pretends it is a linear array.
 */
#define BUS1_HANDLE_BATCH_SIZE (1024)

/**
 * union bus1_handle_entry - batch entry
 * @next:		pointer to next batch entry
 * @handle:		pointer to stored handle
 * @id:			stored handle ID
 *
 * This union represents a single handle-entry in a batch. To support large
 * batches, we only store a limited number of handles consequetively. Once the
 * batch size is reached, a new batch is allocated and linked  This is all
 * hidden in the batch implementation, the details are hidden from the caller.
 */
union bus1_handle_entry {
	union bus1_handle_entry *next;
	struct bus1_handle *handle;
	u64 id;
};

/**
 * struct bus1_handle_batch - dynamic set of handles
 * @n_entries:		number of ids or handles this batch carries (excluding
 *			.next pointers)
 * @n_handles:		number of slots that actually have a handle pinned
 * @entries:		stored entries
 *
 * The batch object allows handling multiple handles in a single set. Each
 * batch can store an unlimited number of handles, and internally they're
 * grouped into batches of BUS1_HANDLE_BATCH_SIZE entries.
 *
 * All handles are put into the trailing array @entries. However, at most
 * BUS1_HANDLE_BATCH_SIZE entries are stored there. If this number is exceeded,
 * then batch->entries[BUS1_HANDLE_BATCH_SIZE].next points to the next
 * dynamically allocated array of bus1_handle_entry objects. This can be
 * extended as often as you want, to support unlimited sized batches.
 *
 * The caller must not access @entries directly!
 */
struct bus1_handle_batch {
	size_t n_entries;
	size_t n_handles;
	union bus1_handle_entry entries[0];
};

/**
 * struct bus1_handle_transfer - handle transfer context
 * @n_new:		number of newly allocated nodes
 * @batch:		associated handles
 *
 * The bus1_handle_transfer object contains context state for message
 * transactions, regarding handle transfers. It pins all the local handles of
 * the sending peer for the whole duration of a transaction. It is usually used
 * to instantiate bus1_handle_inflight objects for each destination.
 *
 * A transfer context should have the same lifetime as the parent transaction
 * context.
 *
 * Note that the tail of the object contains a dynamically sized array with the
 * first handle-set of @batch.
 */
struct bus1_handle_transfer {
	size_t n_new;
	struct bus1_handle_batch batch;
	/* @batch must be last */
};

/**
 * struct bus1_handle_inflight - set of inflight handles
 * @n_new:		number of newly allocated nodes
 * @batch:		associated handles
 *
 * The bus1_handle_inflight object carries state for each message instance
 * regarding handle transfers. That is, it contains all the handle instances
 * for the receiver of the message (while bus1_handle_transfer pins the handles
 * of the sender). This object is usually embedded in the queue-entry that is
 * used to send a single message instance to another peer.
 *
 * Note that the tail of the object contains a dynamically sized array with the
 * first handle-set of @batch.
 */
struct bus1_handle_inflight {
	size_t n_new;
	struct bus1_handle_batch batch;
	/* @batch must be last */
};

/* api */
u64 bus1_handle_from_queue(struct bus1_queue_node *node,
			   struct bus1_peer_info *peer_info,
			   bool drop);
int bus1_handle_pair(struct bus1_peer *peer,
		     struct bus1_peer *clone,
		     u64 *node_idp,
		     u64 *handle_idp);
int bus1_handle_release_by_id(struct bus1_peer_info *peer_info, u64 id);
int bus1_handle_destroy_by_id(struct bus1_peer_info *peer_info, u64 id);
void bus1_handle_flush_all(struct bus1_peer_info *peer_info);

/* destination context */
void bus1_handle_dest_init(struct bus1_handle_dest *dest);
void bus1_handle_dest_destroy(struct bus1_handle_dest *dest,
			      struct bus1_peer_info *peer_info);
int bus1_handle_dest_import(struct bus1_handle_dest *dest,
			    struct bus1_peer *peer,
			    u64 __user *idp);
u64 bus1_handle_dest_export(struct bus1_handle_dest *dest,
			    struct bus1_peer_info *peer_info,
			    u64 timestamp,
			    bool commit);

/* transfer contexts */
void bus1_handle_transfer_init(struct bus1_handle_transfer *transfer,
			       size_t n_entries);
void bus1_handle_transfer_destroy(struct bus1_handle_transfer *transfer,
				  struct bus1_peer_info *peer_info);
int bus1_handle_transfer_import(struct bus1_handle_transfer *transfer,
				struct bus1_peer_info *peer_info,
				const u64 __user *ids,
				size_t n_ids);
void bus1_handle_transfer_install(struct bus1_handle_transfer *transfer,
				  struct bus1_peer *peer);
int bus1_handle_transfer_export(struct bus1_handle_transfer *transfer,
				struct bus1_peer_info *peer_info,
				u64 __user *ids,
				size_t n_ids);

/* inflight tracking */
void bus1_handle_inflight_init(struct bus1_handle_inflight *inflight,
			       size_t n_entries);
void bus1_handle_inflight_destroy(struct bus1_handle_inflight *inflight,
				  struct bus1_peer_info *peer_info);
int bus1_handle_inflight_import(struct bus1_handle_inflight *inflight,
				struct bus1_peer_info *peer_info,
				struct bus1_handle_transfer *transfer);
void bus1_handle_inflight_install(struct bus1_handle_inflight *inflight,
				  struct bus1_peer *dst);
size_t bus1_handle_inflight_walk(struct bus1_handle_inflight *inflight,
				 struct bus1_peer_info *peer_info,
				 size_t *pos,
				 void **iter,
				 u64 *ids,
				 u64 timestamp);
void bus1_handle_inflight_commit(struct bus1_handle_inflight *inflight,
				 struct bus1_peer_info *peer_info,
				 u64 timestamp);

/**
 * bus1_handle_batch_inline_size() - calculate required inline size
 * @n_entries:		size of batch
 *
 * This calculates the size of the trailing entries array that is to be
 * embedded into a "struct bus1_handle_batch". That is, to statically allocate
 * a batch, you need a memory block of size:
 *
 *     sizeof(struct bus1_handle_batch) + bus1_handle_batch_inline_size(n);
 *
 * where 'n' is the number of entries to store. Note that @n is capped. You
 * still need to call bus1_handle_batch_create() afterwards, to make sure the
 * memory is properly allocated, in case it does not fit into a single set.
 *
 * Return: Size of required trailing bytes of a batch structure.
 */
static inline size_t bus1_handle_batch_inline_size(size_t n_entries)
{
	if (n_entries < BUS1_HANDLE_BATCH_SIZE)
		return sizeof(union bus1_handle_entry) * n_entries;

	return sizeof(union bus1_handle_entry) * (BUS1_HANDLE_BATCH_SIZE + 1);
}

#endif /* __BUS1_HANDLE_H */
