/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "macro.h"

typedef struct UIDRangeEntry {
        uid_t start, nr;
} UIDRangeEntry;

typedef struct UIDRange {
        UIDRangeEntry *entries;
        size_t n_entries;
} UIDRange;

UIDRange *uid_range_free(UIDRange *range);
DEFINE_TRIVIAL_CLEANUP_FUNC(UIDRange*, uid_range_free);

int uid_range_add_internal(UIDRange **range, uid_t start, uid_t nr, bool coalesce);
static inline int uid_range_add(UIDRange **range, uid_t start, uid_t nr) {
        return uid_range_add_internal(range, start, nr, true);
}
int uid_range_add_str(UIDRange **range, const char *s);

int uid_range_next_lower(const UIDRange *range, uid_t *uid);

bool uid_range_covers(const UIDRange *range, uid_t start, uid_t nr);
static inline bool uid_range_contains(const UIDRange *range, uid_t uid) {
        return uid_range_covers(range, uid, 1);
}

int uid_map_read_one(FILE *f, uid_t *ret_base, uid_t *ret_shift, uid_t *ret_range);

int uid_range_load_userns(UIDRange **ret, const char *path);
