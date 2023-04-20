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

static inline size_t uid_range_entries(const UidRange *range) {
        return range ? range->n_entries : 0;
}

static inline unsigned uid_range_size(const UidRange *range) {
        if (!range)
                return 0;

        unsigned n = 0;

        FOREACH_ARRAY(e, range->entries, range->n_entries)
                n += e->nr;

        return n;
}

static inline bool uid_range_is_empty(const UidRange  *range) {

        if (!range)
                return true;

        FOREACH_ARRAY(e, range->entries, range->n_entries)
                if (e->nr > 0)
                        return false;

        return true;
}

bool uid_range_equal(const UidRange *a, const UidRange *b);

typedef enum UidRangeUsernsMode {
        UID_RANGE_USERNS_INSIDE,
        UID_RANGE_USERNS_OUTSIDE,
        GID_RANGE_USERNS_INSIDE,
        GID_RANGE_USERNS_OUTSIDE,
        _UID_RANGE_USERNS_MODE_MAX,
        _UID_RANGE_USERNS_MODE_INVALID = -EINVAL,
} UidRangeUsernsMode;

int uid_range_load_userns(UidRange **ret, const char *path, UidRangeUsernsMode mode);
int uid_range_load_userns_by_fd(UidRange **ret, int userns_fd, UidRangeUsernsMode mode);

bool uid_range_overlaps(const UidRange *range, uid_t start, uid_t nr);
