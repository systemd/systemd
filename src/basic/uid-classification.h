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

static inline bool uid_in_range(uid_t uid, UGIDRangeFlags flags) {
        assert(flags);

        if (FLAGS_SET(flags, UGID_RANGE_DYNAMIC))
                if (DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX)
                        return true;

        if (FLAGS_SET(flags, UGID_RANGE_CONTAINER))
                if (CONTAINER_UID_BASE_MIN <= uid && uid <= CONTAINER_UID_BASE_MAX)
                        return true;

        if (FLAGS_SET(flags, UGID_RANGE_SYSTEM)) {
                const UGIDAllocationRange *defs;
                assert_se(defs = acquire_ugid_allocation_range());

                if (uid <= defs->system_uid_max)
                        return true;
        }

        return false;
}

static inline bool gid_in_range(gid_t gid, UGIDRangeFlags flags) {

        if (FLAGS_SET(flags, UGID_RANGE_SYSTEM)) {
                const UGIDAllocationRange *defs;
                assert_se(defs = acquire_ugid_allocation_range());

                return gid <= defs->system_gid_max;
        }

        return uid_in_range((uid_t) gid, flags);
}

bool uid_for_system_journal(uid_t uid);
