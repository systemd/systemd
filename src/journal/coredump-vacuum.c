/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/statvfs.h>

#include "alloc-util.h"
#include "coredump-vacuum.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "macro.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"
#include "util.h"

#define DEFAULT_MAX_USE_LOWER (uint64_t) (1ULL*1024ULL*1024ULL)           /* 1 MiB */
#define DEFAULT_MAX_USE_UPPER (uint64_t) (4ULL*1024ULL*1024ULL*1024ULL)   /* 4 GiB */
#define DEFAULT_KEEP_FREE_UPPER (uint64_t) (4ULL*1024ULL*1024ULL*1024ULL) /* 4 GiB */
#define DEFAULT_KEEP_FREE (uint64_t) (1024ULL*1024ULL)                    /* 1 MB */

struct vacuum_candidate {
        unsigned n_files;
        char *oldest_file;
        usec_t oldest_mtime;
};

static void vacuum_candidate_free(struct vacuum_candidate *c) {
        if (!c)
                return;

        free(c->oldest_file);
        free(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct vacuum_candidate*, vacuum_candidate_free);

static void vacuum_candidate_hasmap_free(Hashmap *h) {
        struct vacuum_candidate *c;

        while ((c = hashmap_steal_first(h)))
                vacuum_candidate_free(c);

        hashmap_free(h);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, vacuum_candidate_hasmap_free);

static int uid_from_file_name(const char *filename, uid_t *uid) {
        const char *p, *e, *u;

        p = startswith(filename, "core.");
        if (!p)
                return -EINVAL;

        /* Skip the comm field */
        p = strchr(p, '.');
        if (!p)
                return -EINVAL;
        p++;

        /* Find end up UID */
        e = strchr(p, '.');
        if (!e)
                return -EINVAL;

        u = strndupa(p, e-p);
        return parse_uid(u, uid);
}

static bool vacuum_necessary(int fd, uint64_t sum, uint64_t keep_free, uint64_t max_use) {
        uint64_t fs_size = 0, fs_free = (uint64_t) -1;
        struct statvfs sv;

        assert(fd >= 0);

        if (fstatvfs(fd, &sv) >= 0) {
                fs_size = sv.f_frsize * sv.f_blocks;
                fs_free = sv.f_frsize * sv.f_bfree;
        }

        if (max_use == (uint64_t) -1) {

                if (fs_size > 0) {
                        max_use = PAGE_ALIGN(fs_size / 10); /* 10% */

                        if (max_use > DEFAULT_MAX_USE_UPPER)
                                max_use = DEFAULT_MAX_USE_UPPER;

                        if (max_use < DEFAULT_MAX_USE_LOWER)
                                max_use = DEFAULT_MAX_USE_LOWER;
                } else
                        max_use = DEFAULT_MAX_USE_LOWER;
        } else
                max_use = PAGE_ALIGN(max_use);

        if (max_use > 0 && sum > max_use)
                return true;

        if (keep_free == (uint64_t) -1) {

                if (fs_size > 0) {
                        keep_free = PAGE_ALIGN((fs_size * 3) / 20); /* 15% */

                        if (keep_free > DEFAULT_KEEP_FREE_UPPER)
                                keep_free = DEFAULT_KEEP_FREE_UPPER;
                } else
                        keep_free = DEFAULT_KEEP_FREE;
        } else
                keep_free = PAGE_ALIGN(keep_free);

        if (keep_free > 0 && fs_free < keep_free)
                return true;

        return false;
}

int coredump_vacuum(int exclude_fd, uint64_t keep_free, uint64_t max_use) {
        _cleanup_closedir_ DIR *d = NULL;
        struct stat exclude_st;
        int r;

        if (keep_free == 0 && max_use == 0)
                return 0;

        if (exclude_fd >= 0) {
                if (fstat(exclude_fd, &exclude_st) < 0)
                        return log_error_errno(errno, "Failed to fstat(): %m");
        }

        /* This algorithm will keep deleting the oldest file of the
         * user with the most coredumps until we are back in the size
         * limits. Note that vacuuming for journal files is different,
         * because we rely on rate-limiting of the messages there,
         * to avoid being flooded. */

        d = opendir("/var/lib/systemd/coredump");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Can't open coredump directory: %m");
        }

        for (;;) {
                _cleanup_(vacuum_candidate_hasmap_freep) Hashmap *h = NULL;
                struct vacuum_candidate *worst = NULL;
                struct dirent *de;
                uint64_t sum = 0;

                rewinddir(d);

                FOREACH_DIRENT(de, d, goto fail) {
                        struct vacuum_candidate *c;
                        struct stat st;
                        uid_t uid;
                        usec_t t;

                        r = uid_from_file_name(de->d_name, &uid);
                        if (r < 0)
                                continue;

                        if (fstatat(dirfd(d), de->d_name, &st, AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW) < 0) {
                                if (errno == ENOENT)
                                        continue;

                                log_warning_errno(errno, "Failed to stat /var/lib/systemd/coredump/%s: %m", de->d_name);
                                continue;
                        }

                        if (!S_ISREG(st.st_mode))
                                continue;

                        if (exclude_fd >= 0 &&
                            exclude_st.st_dev == st.st_dev &&
                            exclude_st.st_ino == st.st_ino)
                                continue;

                        r = hashmap_ensure_allocated(&h, NULL);
                        if (r < 0)
                                return log_oom();

                        t = timespec_load(&st.st_mtim);

                        c = hashmap_get(h, UID_TO_PTR(uid));
                        if (c) {

                                if (t < c->oldest_mtime) {
                                        char *n;

                                        n = strdup(de->d_name);
                                        if (!n)
                                                return log_oom();

                                        free(c->oldest_file);
                                        c->oldest_file = n;
                                        c->oldest_mtime = t;
                                }

                        } else {
                                _cleanup_(vacuum_candidate_freep) struct vacuum_candidate *n = NULL;

                                n = new0(struct vacuum_candidate, 1);
                                if (!n)
                                        return log_oom();

                                n->oldest_file = strdup(de->d_name);
                                if (!n->oldest_file)
                                        return log_oom();

                                n->oldest_mtime = t;

                                r = hashmap_put(h, UID_TO_PTR(uid), n);
                                if (r < 0)
                                        return log_oom();

                                c = n;
                                n = NULL;
                        }

                        c->n_files++;

                        if (!worst ||
                            worst->n_files < c->n_files ||
                            (worst->n_files == c->n_files && c->oldest_mtime < worst->oldest_mtime))
                                worst = c;

                        sum += st.st_blocks * 512;
                }

                if (!worst)
                        break;

                r = vacuum_necessary(dirfd(d), sum, keep_free, max_use);
                if (r <= 0)
                        return r;

                if (unlinkat(dirfd(d), worst->oldest_file, 0) < 0) {

                        if (errno == ENOENT)
                                continue;

                        return log_error_errno(errno, "Failed to remove file %s: %m", worst->oldest_file);
                } else
                        log_info("Removed old coredump %s.", worst->oldest_file);
        }

        return 0;

fail:
        return log_error_errno(errno, "Failed to read directory: %m");
}
