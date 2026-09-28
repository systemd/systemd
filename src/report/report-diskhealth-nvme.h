/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct NVMeHealth {
        uint8_t critical_warning;       /* bitmask, see NVMe Base Specification, SMART / Health Information log */
        uint8_t available_spare;        /* percent */
        uint8_t percentage_used;        /* percent, may exceed 100 */
        uint64_t media_errors;
        uint64_t power_cycles;
        uint64_t power_on_hours;
} NVMeHealth;

int nvme_read_health(int fd, NVMeHealth *ret);
