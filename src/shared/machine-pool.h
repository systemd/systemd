/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdint.h>

#include "sd-bus.h"

/* Grow the /var/lib/machines directory after each 10MiB written */
#define GROW_INTERVAL_BYTES (UINT64_C(10) * UINT64_C(1024) * UINT64_C(1024))

int setup_machine_directory(uint64_t size, sd_bus_error *error);
int grow_machine_directory(void);
