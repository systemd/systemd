/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

bool uid_is_system(uid_t uid);
bool gid_is_system(gid_t gid);

static inline bool uid_is_dynamic(uid_t uid) {
        return DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX;
}

static inline bool gid_is_dynamic(gid_t gid) {
        return uid_is_dynamic((uid_t) gid);
}

static inline bool uid_is_container(uid_t uid) {
        return CONTAINER_UID_BASE_MIN <= uid && uid <= CONTAINER_UID_BASE_MAX;
}

static inline bool gid_is_container(gid_t gid) {
        return uid_is_container((uid_t) gid);
}

typedef struct UGIDAllocationRange {
        uid_t system_alloc_uid_min;
        uid_t system_uid_max;
        gid_t system_alloc_gid_min;
        gid_t system_gid_max;
} UGIDAllocationRange;

int read_login_defs(UGIDAllocationRange *ret_defs, const char *path, const char *root);
const UGIDAllocationRange *acquire_ugid_allocation_range(void);

bool uid_for_system_journal(uid_t uid);
