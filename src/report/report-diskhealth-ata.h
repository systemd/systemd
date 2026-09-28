/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct ATAHealth {
        int smart_failing;                /* < 0 if unknown */
        uint64_t reallocated_sectors;     /* UINT64_MAX if unknown, and so on */
        uint64_t pending_sectors;
        uint64_t offline_uncorrectable;
        uint64_t power_cycles;
        uint64_t power_on_hours;
} ATAHealth;

#define ATA_HEALTH_NULL                                 \
        (ATAHealth) {                                   \
                .smart_failing = -1,                    \
                .reallocated_sectors = UINT64_MAX,      \
                .pending_sectors = UINT64_MAX,          \
                .offline_uncorrectable = UINT64_MAX,    \
                .power_cycles = UINT64_MAX,             \
                .power_on_hours = UINT64_MAX,           \
        }

int ata_read_health(int fd, ATAHealth *ret);
