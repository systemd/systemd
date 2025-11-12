/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <threads.h>

#include "fiber.h"
#include "string-table.h"

static thread_local sd_fiber *current_fiber = NULL;

static const char* const sd_fiber_state_table[_SD_FIBER_STATE_MAX] = {
        [SD_FIBER_STATE_READY]     = "ready",
        [SD_FIBER_STATE_SUSPENDED] = "suspended",
        [SD_FIBER_STATE_COMPLETED] = "completed",
        [SD_FIBER_STATE_CANCELLED] = "cancelled",
};

DEFINE_STRING_TABLE_LOOKUP(sd_fiber_state, sd_fiber_state_t);

sd_fiber *sd_fiber_current(void) {
        return current_fiber;
}

void sd_fiber_set_current(sd_fiber *f) {
        current_fiber = f;
}
