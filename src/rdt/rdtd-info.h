/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct RdtInfo RdtInfo;
typedef struct RdtInfoL3 RdtInfoL3;

#include "rdtd.h"
#include "rdtd-group.h"

#define L3_CACHE_FILE           "/sys/devices/system/cpu/cpu0/cache/index3/size"

struct RdtInfoL3 {
        uint64_t cache_bytes;

        /* resctrlfs file */
        unsigned int min_cbm_bits;
        unsigned int num_closids;
        uint64_t cbm_mask;

        /* Smallest possible increase of the allocation size in bytes */
        uint64_t granularity;
        /* Max bits of the cbm_mask */
        unsigned int cbm_bits;
        /* Minimal allocatable size in bytes (if different from granularity) */
        uint64_t min;

        unsigned int max_ids; /* socket ids */
};

struct RdtInfo {
        RdtInfoL3 l3_info;
};
