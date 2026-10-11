/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "list.h"

/* A fiber waits for at most one future at a time, so each fiber contains a single FutureWaiter. */
typedef struct FutureWaiter FutureWaiter;
struct FutureWaiter {
        sd_future *fiber;
        sd_future *target;              /* The wait holds a reference on the target. */
        LIST_FIELDS(FutureWaiter, waiters);
};

void future_add_waiter(sd_future *target, FutureWaiter *waiter);
/* Returns the target together with the reference that the wait held on it. */
sd_future* future_remove_waiter(FutureWaiter *waiter);
