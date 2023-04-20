/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "macro.h"

typedef struct UidRangeEntry {
        uid_t start, nr;
} UidRangeEntry;

typedef struct UidRange {
        UidRangeEntry *entries;
        size_t n_entries;
} UidRange;

UidRange *uid_range_free(UidRange *range);
DEFINE_TRIVIAL_CLEANUP_FUNC(UidRange*, uid_range_free);

int uid_range_add_internal(UidRange **range, uid_t start, uid_t nr, bool coalesce);
static inline int uid_range_add(UidRange **range, uid_t start, uid_t nr) {
        return uid_range_add_internal(range, start, nr, true);
}
int uid_range_add_str(UidRange **range, const char *s);

int uid_range_next_lower(const UidRange *range, uid_t *uid);

bool uid_range_covers(const UidRange *range, uid_t start, uid_t nr);
static inline bool uid_range_contains(const UidRange *range, uid_t uid) {
        return uid_range_covers(range, uid, 1);
}

int uid_map_read_one(FILE *f, uid_t *ret_base, uid_t *ret_shift, uid_t *ret_range);

typedef enum UidRangeUsernsMode {
        UID_RANGE_USERNS_INSIDE,
        UID_RANGE_USERNS_OUTSIDE,
        _UID_RANGE_USERNS_MODE_MAX,
        _UID_RANGE_USERNS_MODE_INVALID = -EINVAL,
} UidRangeUsernsMode;

int uid_range_load_userns(UidRange **ret, const char *path, UidRangeUsernsMode mode);

bool uid_range_overlaps(const UidRange *range, uid_t start, uid_t nr);
