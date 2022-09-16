/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "macro.h"
#include "path-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "uid-range.h"
#include "user-util.h"

static bool uid_range_intersect(const UidRange *a, const UidRange *b) {
        assert(a);
        assert(b);

        return a->start <= b->start + b->nr && a->start + a->nr >= b->start;
}

static int uid_range_compare(const UidRange *a, const UidRange *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->start, b->start);
        if (r != 0)
                return r;

        return CMP(a->nr, b->nr);
}

static void uid_range_coalesce(UidRange **p, size_t *n) {
        assert(p);
        assert(n);

        if (*n == 0)
                return;

        typesafe_qsort(*p, *n, uid_range_compare);

        for (size_t i = 0; i < *n; i++) {
                UidRange *x = (*p) + i;

                for (size_t j = i + 1; j < *n; j++) {
                        UidRange *y = (*p)+j;
                        uid_t begin, end;

                        if (!uid_range_intersect(x, y))
                                break;

                        begin = MIN(x->start, y->start);
                        end = MAX(x->start + x->nr, y->start + y->nr);

                        x->start = begin;
                        x->nr = end - begin;

                        if (*n > j+1)
                                memmove(y, y+1, sizeof(UidRange) * (*n - j -1));

                        (*n)--;
                        j--;
                }
        }
}

int uid_range_add_internal(UidRange **p, size_t *n, uid_t start, uid_t nr, bool coalesce) {
        assert(p);
        assert(n);

        if (nr <= 0)
                return 0;

        if (start > UINT32_MAX - nr) /* overflow check */
                return -ERANGE;

        if (!GREEDY_REALLOC(*p, *n + 1))
                return -ENOMEM;

        (*p)[(*n)++] = (UidRange) {
                .start = start,
                .nr = nr,
        };

        if (coalesce)
                uid_range_coalesce(p, n);

        return *n;
}

int uid_range_add_str(UidRange **p, size_t *n, const char *s) {
        uid_t start, end;
        int r;

        assert(p);
        assert(n);
        assert(s);

        r = parse_uid_range(s, &start, &end);
        if (r < 0)
                return r;

        return uid_range_add(p, n, start, end - start + 1);
}

int uid_range_next_lower(const UidRange *p, size_t n, uid_t *uid) {
        uid_t closest = UID_INVALID, candidate;

        assert(p);
        assert(uid);

        if (*uid == 0)
                return -EBUSY;

        candidate = *uid - 1;

        for (size_t i = 0; i < n; i++) {
                uid_t begin, end;

                begin = p[i].start;
                end = p[i].start + p[i].nr - 1;

                if (candidate >= begin && candidate <= end) {
                        *uid = candidate;
                        return 1;
                }

                if (end < candidate)
                        closest = end;
        }

        if (closest == UID_INVALID)
                return -EBUSY;

        *uid = closest;
        return 1;
}

bool uid_range_covers(const UidRange *p, size_t n, uid_t start, uid_t nr) {
        assert(p || n == 0);

        if (nr == 0) /* empty range? always covered... */
                return true;

        if (start > UINT32_MAX - nr) /* range overflows? definitely not covered... */
                return false;

        for (size_t i = 0; i < n; i++)
                if (start >= p[i].start && start + nr <= p[i].start + p[i].nr)
                        return true;

        return false;
}

int uid_range_load_userns(UidRange **p, size_t *n, const char *path) {
        _cleanup_free_ UidRange *q = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t m = 0;
        int r;

        /* If 'path' is NULL loads the UID range of the userns namespace we run. Otherwise load the data from
         * the specified file (which can be either uid_map or gid_map, in case caller needs to deal with GID
         * maps).
         *
         * To simplify things this will modify the passed array in case of later failure. */

        assert(p);
        assert(n);

        if (!path)
                path = "/proc/self/uid_map";

        f = fopen(path, "re");
        if (!f) {
                r = -errno;

                if (r == -ENOENT && path_startswith(path, "/proc/"))
                        return proc_mounted() > 0 ? -EOPNOTSUPP : -ENOSYS;

                return r;
        }

        for (;;) {
                uid_t uid_base, uid_shift, uid_range;
                int k;

                errno = 0;
                k = fscanf(f, UID_FMT " " UID_FMT " " UID_FMT "\n", &uid_base, &uid_shift, &uid_range);
                if (k == EOF) {
                        if (ferror(f))
                                return errno_or_else(EIO);

                        break;
                }
                if (k != 3)
                        return -EBADMSG;

                r = uid_range_add(&q, &m, uid_base, uid_range);
                if (r < 0)
                        return r;
        }

        uid_range_coalesce(&q, &m);

        *p = TAKE_PTR(q);
        *n = m;

        return 0;
}
