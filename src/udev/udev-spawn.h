/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"
#include "time-util.h"

#define READ_END  0
#define WRITE_END 1

typedef struct UdevEvent UdevEvent;

int udev_event_spawn(
                UdevEvent *event,
                usec_t timeout_usec,
                int timeout_signal,
                bool accept_failure,
                const char *cmd,
                char *result,
                size_t ressize,
                bool *ret_truncated);
void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec, int timeout_signal);

static inline usec_t udev_warn_timeout(usec_t timeout_usec) {
        if (timeout_usec == USEC_INFINITY)
                return USEC_INFINITY;

        return DIV_ROUND_UP(timeout_usec, 3);
}
