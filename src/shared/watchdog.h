/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "time-util.h"
#include "util.h"

int watchdog_set_device(char *path);
int watchdog_set_timeout(usec_t *usec);
int watchdog_ping(void);
void watchdog_close(bool disarm);

static inline void watchdog_free_device(void) {
        (void) watchdog_set_device(NULL);
}
