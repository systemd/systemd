/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"
#include "util.h"

const char *watchdog_get_device(void);
usec_t watchdog_get_last_ping(clockid_t clock);

int watchdog_set_device(const char *path);
int watchdog_setup(usec_t timeout);
int watchdog_setup_pretimeout(usec_t usec);
int watchdog_setup_pretimeout_governor(const char *governor);
int watchdog_ping(void);
void watchdog_close(bool disarm);
usec_t watchdog_runtime_wait(void);

static inline void watchdog_free_device(void) {
        (void) watchdog_set_device(NULL);
}
