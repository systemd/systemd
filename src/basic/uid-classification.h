/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

typedef struct UGIDAllocationRange {
        uid_t system_alloc_uid_min;
        uid_t system_uid_max;
        gid_t system_alloc_gid_min;
        gid_t system_gid_max;
} UGIDAllocationRange;

int read_login_defs(UGIDAllocationRange *ret_defs, const char *path, const char *root);
const UGIDAllocationRange *acquire_ugid_allocation_range(void);

typedef enum UGIDRangeFlags {
        UGID_RANGE_SYSTEM     = 1 << 0,
        UGID_RANGE_DYNAMIC    = 1 << 1,
        UGID_RANGE_CONTAINER  = 1 << 2,
} UGIDRangeFlags;

bool uid_in_range(uid_t uid, UGIDRangeFlags flags);
bool gid_in_range(uid_t uid, UGIDRangeFlags flags);

bool uid_is_dynamic(uid_t uid);

static inline bool gid_is_dynamic(gid_t gid) {
        return uid_is_dynamic((uid_t) gid);
}

bool uid_for_system_journal(uid_t uid);
