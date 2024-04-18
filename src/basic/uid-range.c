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
#include "process-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "uid-range.h"
#include "user-util.h"

UIDRange *uid_range_free(UIDRange *range) {
        if (!range)
                return NULL;

        free(range->entries);
        return mfree(range);
}

static bool uid_range_entry_intersect(const UIDRangeEntry *a, const UIDRangeEntry *b) {
        assert(a);
        assert(b);

        return a->start <= b->start + b->nr && a->start + a->nr >= b->start;
}

static int uid_range_entry_compare(const UIDRangeEntry *a, const UIDRangeEntry *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->start, b->start);
        if (r != 0)
                return r;

        return CMP(a->nr, b->nr);
}

static void uid_range_coalesce(UIDRange *range) {
        assert(range);

        if (range->n_entries <= 0)
                return;

        typesafe_qsort(range->entries, range->n_entries, uid_range_entry_compare);

        for (size_t i = 0; i < range->n_entries; i++) {
                UIDRangeEntry *x = range->entries + i;

                for (size_t j = i + 1; j < range->n_entries; j++) {
                        UIDRangeEntry *y = range->entries + j;
                        uid_t begin, end;

                        if (!uid_range_entry_intersect(x, y))
                                break;

                        begin = MIN(x->start, y->start);
                        end = MAX(x->start + x->nr, y->start + y->nr);

                        x->start = begin;
                        x->nr = end - begin;

                        if (range->n_entries > j + 1)
                                memmove(y, y + 1, sizeof(UIDRangeEntry) * (range->n_entries - j - 1));

                        range->n_entries--;
                        j--;
                }
        }
}

int uid_range_add_internal(UIDRange **range, uid_t start, uid_t nr, bool coalesce) {
        _cleanup_(uid_range_freep) UIDRange *range_new = NULL;
        UIDRange *p;

        assert(range);

        if (nr <= 0)
                return 0;

        if (start > UINT32_MAX - nr) /* overflow check */
                return -ERANGE;

        if (*range)
                p = *range;
        else {
                range_new = new0(UIDRange, 1);
                if (!range_new)
                        return -ENOMEM;

                p = range_new;
        }

        if (!GREEDY_REALLOC(p->entries, p->n_entries + 1))
                return -ENOMEM;

        p->entries[p->n_entries++] = (UIDRangeEntry) {
                .start = start,
                .nr = nr,
        };

        if (coalesce)
                uid_range_coalesce(p);

        TAKE_PTR(range_new);
        *range = p;

        return 0;
}

int uid_range_add_str(UIDRange **range, const char *s) {
        uid_t start, end;
        int r;

        assert(range);
        assert(s);

        r = parse_uid_range(s, &start, &end);
        if (r < 0)
                return r;

        return uid_range_add_internal(range, start, end - start + 1, /* coalesce = */ true);
}

int uid_range_next_lower(const UIDRange *range, uid_t *uid) {
        uid_t closest = UID_INVALID, candidate;

        assert(range);
        assert(uid);

        if (*uid == 0)
                return -EBUSY;

        candidate = *uid - 1;

        for (size_t i = 0; i < range->n_entries; i++) {
                uid_t begin, end;

                begin = range->entries[i].start;
                end = range->entries[i].start + range->entries[i].nr - 1;

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

bool uid_range_covers(const UIDRange *range, uid_t start, uid_t nr) {
        if (nr == 0) /* empty range? always covered... */
                return true;

        if (start > UINT32_MAX - nr) /* range overflows? definitely not covered... */
                return false;

        if (!range)
                return false;

        FOREACH_ARRAY(i, range->entries, range->n_entries)
                if (start >= i->start &&
                    start + nr <= i->start + i->nr)
                        return true;

        return false;
}

int uid_map_read_one(FILE *f, uid_t *ret_base, uid_t *ret_shift, uid_t *ret_range) {
        uid_t uid_base, uid_shift, uid_range;
        int r;

        assert(f);
        assert(ret_base);
        assert(ret_shift);
        assert(ret_range);

        errno = 0;
        r = fscanf(f, UID_FMT " " UID_FMT " " UID_FMT "\n", &uid_base, &uid_shift, &uid_range);
        if (r == EOF)
                return errno_or_else(ENOMSG);
        assert(r >= 0);
        if (r != 3)
                return -EBADMSG;

        *ret_base = uid_base;
        *ret_shift = uid_shift;
        *ret_range = uid_range;

        return 0;
}

int uid_range_load_userns(const char *path, UIDRangeUsernsMode mode, UIDRange **ret) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* If 'path' is NULL loads the UID range of the userns namespace we run. Otherwise load the data from
         * the specified file (which can be either uid_map or gid_map, in case caller needs to deal with GID
         * maps).
         *
         * To simplify things this will modify the passed array in case of later failure. */

        assert(mode >= 0);
        assert(mode < _UID_RANGE_USERNS_MODE_MAX);
        assert(ret);

        if (!path)
                path = IN_SET(mode, UID_RANGE_USERNS_INSIDE, UID_RANGE_USERNS_OUTSIDE) ? "/proc/self/uid_map" : "/proc/self/gid_map";

        f = fopen(path, "re");
        if (!f) {
                r = -errno;

                if (r == -ENOENT && path_startswith(path, "/proc/"))
                        return proc_mounted() > 0 ? -EOPNOTSUPP : -ENOSYS;

                return r;
        }

        range = new0(UIDRange, 1);
        if (!range)
                return -ENOMEM;

        for (;;) {
                uid_t uid_base, uid_shift, uid_range;

                r = uid_map_read_one(f, &uid_base, &uid_shift, &uid_range);
                if (r == -ENOMSG)
                        break;
                if (r < 0)
                        return r;

                r = uid_range_add_internal(
                                &range,
                                IN_SET(mode, UID_RANGE_USERNS_INSIDE, GID_RANGE_USERNS_INSIDE) ? uid_base : uid_shift,
                                uid_range,
                                /* coalesce = */ false);
                if (r < 0)
                        return r;
        }

        uid_range_coalesce(range);

        *ret = TAKE_PTR(range);
        return 0;
}

int uid_range_load_userns_by_fd(int userns_fd, UIDRangeUsernsMode mode, UIDRange **ret) {
        _cleanup_(close_pairp) int pfd[2] = EBADF_PAIR;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        ssize_t n;
        char x;
        int r;

        assert(userns_fd >= 0);
        assert(mode >= 0);
        assert(mode < _UID_RANGE_USERNS_MODE_MAX);
        assert(ret);

        if (pipe2(pfd, O_CLOEXEC) < 0)
                return -errno;

        r = safe_fork_full(
                        "(sd-mkuserns)",
                        /* stdio_fds= */ NULL,
                        (int[]) { pfd[1], userns_fd }, 2,
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL,
                        &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child. */

                if (setns(userns_fd, CLONE_NEWUSER) < 0) {
                        log_debug_errno(errno, "Failed to join userns: %m");
                        _exit(EXIT_FAILURE);
                }

                userns_fd = safe_close(userns_fd);

                n = write(pfd[1], &(const char) { 'x' }, 1);
                if (n < 0) {
                        log_debug_errno(errno, "Failed to write to fifo: %m");
                        _exit(EXIT_FAILURE);
                }
                assert(n == 1);

                freeze();
        }

        pfd[1] = safe_close(pfd[1]);

        n = read(pfd[0], &x, 1);
        if (n < 0)
                return -errno;
        if (n == 0)
                return -EPROTO;
        assert(n == 1);
        assert(x == 'x');

        const char *p = procfs_file_alloca(
                        pid,
                        IN_SET(mode, UID_RANGE_USERNS_INSIDE, UID_RANGE_USERNS_OUTSIDE) ? "uid_map" : "gid_map");

        return uid_range_load_userns(p, mode, ret);
}

bool uid_range_overlaps(const UIDRange *range, uid_t start, uid_t nr) {

        if (!range)
                return false;

        /* Avoid overflow */
        if (start > UINT32_MAX - nr)
                nr = UINT32_MAX - start;

        if (nr == 0)
                return false;

        FOREACH_ARRAY(entry, range->entries, range->n_entries)
                if (start < entry->start + entry->nr &&
                    start + nr >= entry->start)
                        return true;

        return false;
}

bool uid_range_equal(const UIDRange *a, const UIDRange *b) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        if (a->n_entries != b->n_entries)
                return false;

        for (size_t i = 0; i < a->n_entries; i++) {
                if (a->entries[i].start != b->entries[i].start)
                        return false;
                if (a->entries[i].nr != b->entries[i].nr)
                        return false;
        }

        return true;
}
