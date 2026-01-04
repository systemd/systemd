/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <threads.h>

#include "fiber-def.h"
#include "string-table.h"

static thread_local Fiber *current_fiber = NULL;

static const char* const fiber_state_table[_FIBER_STATE_MAX] = {
        [FIBER_STATE_READY]     = "ready",
        [FIBER_STATE_SUSPENDED] = "suspended",
        [FIBER_STATE_COMPLETED] = "completed",
        [FIBER_STATE_CANCELLED] = "cancelled",
};

DEFINE_STRING_TABLE_LOOKUP(fiber_state, FiberState);

Fiber *fiber_get_current(void) {
        return current_fiber;
}

void fiber_set_current(Fiber *f) {
        current_fiber = f;
}
