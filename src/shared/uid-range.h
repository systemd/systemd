/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

typedef struct UidRange {
        uid_t start, nr;
} UidRange;

int uid_range_add(UidRange **p, unsigned *n, uid_t start, uid_t nr);
int uid_range_add_str(UidRange **p, unsigned *n, const char *s);

int uid_range_next_lower(const UidRange *p, unsigned n, uid_t *uid);
bool uid_range_contains(const UidRange *p, unsigned n, uid_t uid);
