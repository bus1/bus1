#ifndef __BUS1_TRANSACTION_H
#define __BUS1_TRANSACTION_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Message Transactions
 *
 * XXX
 */

#include <linux/kernel.h>
#include <uapi/linux/bus1.h>

struct bus1_transaction;

struct bus1_transaction *
bus1_transaction_new_from_user(struct bus1_peer_info *peer_info,
			       struct bus1_cmd_send *param,
			       void *buf,
			       size_t buf_len,
			       bool is_compat);
struct bus1_transaction *
bus1_transaction_free(struct bus1_transaction *transaction, bool do_free);

int bus1_transaction_instantiate_for_id(struct bus1_transaction *transaction,
					struct bus1_user *user,
					u64 peer_id);
void bus1_transaction_commit(struct bus1_transaction *transaction);
int bus1_transaction_commit_for_id(struct bus1_transaction *transaction,
				   struct bus1_user *user,
				   u64 peer_id);

#endif /* __BUS1_TRANSACTION_H */
