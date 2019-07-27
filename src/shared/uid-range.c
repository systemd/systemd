/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"
#include "sort-util.h"
#include "uid-range.h"
#include "user-util.h"

static bool uid_range_intersect(UidRange *range, uid_t start, uid_t nr) {
        assert(range);

        return range->start <= start + nr &&
                range->start + range->nr >= start;
}

static void uid_range_coalesce(UidRange **p, unsigned *n) {
        unsigned i, j;

        assert(p);
        assert(n);

        for (i = 0; i < *n; i++) {
                for (j = i + 1; j < *n; j++) {
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

int uid_range_add(UidRange **p, unsigned *n, uid_t start, uid_t nr) {
        bool found = false;
        UidRange *x;
        unsigned i;

        assert(p);
        assert(n);

        if (nr <= 0)
                return 0;

        for (i = 0; i < *n; i++) {
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

int uid_range_add_str(UidRange **p, unsigned *n, const char *s) {
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

                b = strndupa(s, t - s);
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

int uid_range_next_lower(const UidRange *p, unsigned n, uid_t *uid) {
        uid_t closest = UID_INVALID, candidate;
        unsigned i;

        assert(p);
        assert(uid);

        candidate = *uid - 1;

        for (i = 0; i < n; i++) {
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

bool uid_range_contains(const UidRange *p, unsigned n, uid_t uid) {
        unsigned i;

        assert(p);
        assert(uid);

        for (i = 0; i < n; i++)
                if (uid >= p[i].start && uid < p[i].start + p[i].nr)
                        return true;

        return false;
}
