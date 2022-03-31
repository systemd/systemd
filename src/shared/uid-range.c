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

static bool uid_range_intersect(UidRange *range, uid_t start, uid_t nr) {
        assert(range);

        return range->start <= start + nr &&
                range->start + range->nr >= start;
}

static void uid_range_coalesce(UidRange **p, size_t *n) {
        assert(p);
        assert(n);

        for (size_t i = 0; i < *n; i++) {
                for (size_t j = i + 1; j < *n; j++) {
                        UidRange *x = (*p)+i, *y = (*p)+j;

                        if (uid_range_intersect(x, y->start, y->nr)) {
                                uid_t begin, end;

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
}

static int uid_range_compare(const UidRange *a, const UidRange *b) {
        int r;

        r = CMP(a->start, b->start);
        if (r != 0)
                return r;

        return CMP(a->nr, b->nr);
}

int uid_range_add(UidRange **p, size_t *n, uid_t start, uid_t nr) {
        bool found = false;
        UidRange *x;

        assert(p);
        assert(n);

        if (nr <= 0)
                return 0;

        if (start > UINT32_MAX - nr) /* overflow check */
                return -ERANGE;

        for (size_t i = 0; i < *n; i++) {
                x = (*p) + i;
                if (uid_range_intersect(x, start, nr)) {
                        found = true;
                        break;
                }
        }

        if (found) {
                uid_t begin, end;

                begin = MIN(x->start, start);
                end = MAX(x->start + x->nr, start + nr);

                x->start = begin;
                x->nr = end - begin;
        } else {
                UidRange *t;

                t = reallocarray(*p, *n + 1, sizeof(UidRange));
                if (!t)
                        return -ENOMEM;

                *p = t;
                x = t + ((*n) ++);

                x->start = start;
                x->nr = nr;
        }

        typesafe_qsort(*p, *n, uid_range_compare);
        uid_range_coalesce(p, n);

        return *n;
}

int uid_range_add_str(UidRange **p, size_t *n, const char *s) {
        uid_t start, nr;
        const char *t;
        int r;

        assert(p);
        assert(n);
        assert(s);

        t = strchr(s, '-');
        if (t) {
                char *b;
                uid_t end;

                b = strndupa_safe(s, t - s);
                r = parse_uid(b, &start);
                if (r < 0)
                        return r;

                r = parse_uid(t+1, &end);
                if (r < 0)
                        return r;

                if (end < start)
                        return -EINVAL;

                nr = end - start + 1;
        } else {
                r = parse_uid(s, &start);
                if (r < 0)
                        return r;

                nr = 1;
        }

        return uid_range_add(p, n, start, nr);
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
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* If 'path' is NULL loads the UID range of the userns namespace we run. Otherwise load the data from
         * the specified file (which can be either uid_map or gid_map, in case caller needs to deal with GID
         * maps).
         *
         * To simplify things this will modify the passed array in case of later failure. */

        if (!path)
                path = "/proc/self/uid_map";

        f = fopen(path, "re");
        if (!f) {
                r = -errno;

                if (r == -ENOENT && path_startswith(path, "/proc/") && proc_mounted() > 0)
                        return -EOPNOTSUPP;

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

                        return 0;
                }
                if (k != 3)
                        return -EBADMSG;

                r = uid_range_add(p, n, uid_base, uid_range);
                if (r < 0)
                        return r;
        }
}
