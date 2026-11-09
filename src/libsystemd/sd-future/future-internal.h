/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "list.h"

/* sd_fiber_is_running() also returns true in a blocking region, where a suspension aborts. Fiber-aware
 * helpers check fiber_can_suspend() before they take their suspending path. */
_sync_ bool fiber_can_suspend(void) _suspend_guard_;

/* A fiber waits for at most one future at a time, so each fiber contains a single FutureWaiter. */
typedef struct FutureWaiter FutureWaiter;
struct FutureWaiter {
        sd_future *fiber;
        sd_future *target;              /* The wait holds a reference on the target. */
        LIST_FIELDS(FutureWaiter, waiters);
};

_sync_ void future_add_waiter(sd_future *target, FutureWaiter *waiter);
/* Returns the target together with the reference that the wait held on it. */
_sync_ sd_future* future_remove_waiter(FutureWaiter *waiter);
