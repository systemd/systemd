/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "journal-def.h"
#include "journal-file.h"
#include "journal-vacuum.h"
#include "sd-id128.h"
#include "util.h"

struct vacuum_info {
        off_t usage;
        char *filename;

        uint64_t realtime;
        sd_id128_t seqnum_id;
        uint64_t seqnum;

        bool have_seqnum;
};

static int vacuum_compare(const void *_a, const void *_b) {
        const struct vacuum_info *a, *b;

        a = _a;
        b = _b;

        if (a->have_seqnum && b->have_seqnum &&
            sd_id128_equal(a->seqnum_id, b->seqnum_id)) {
                if (a->seqnum < b->seqnum)
                        return -1;
                else if (a->seqnum > b->seqnum)
                        return 1;
                else
                        return 0;
        }

        if (a->realtime < b->realtime)
                return -1;
        else if (a->realtime > b->realtime)
                return 1;
        else if (a->have_seqnum && b->have_seqnum)
                return memcmp(&a->seqnum_id, &b->seqnum_id, 16);
        else
                return strcmp(a->filename, b->filename);
}

int journal_directory_vacuum(const char *directory, uint64_t max_use, uint64_t min_free) {
        DIR *d;
        int r = 0;
        struct vacuum_info *list = NULL;
        unsigned n_list = 0, n_allocated = 0, i;
        uint64_t sum = 0;

        assert(directory);

        if (max_use <= 0)
                return 0;

        d = opendir(directory);
        if (!d)
                return -errno;

        for (;;) {
                int k;
                struct dirent buf, *de;
                size_t q;
                struct stat st;
                char *p;
                unsigned long long seqnum = 0, realtime;
                sd_id128_t seqnum_id;
                bool have_seqnum;

                k = readdir_r(d, &buf, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                if (!S_ISREG(st.st_mode))
                        continue;

                q = strlen(de->d_name);

                if (endswith(de->d_name, ".journal")) {

                        /* Vacuum archived files */

                        if (q < 1 + 32 + 1 + 16 + 1 + 16 + 8)
                                continue;

                        if (de->d_name[q-8-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1-32-1] != '@')
                                continue;

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        de->d_name[q-8-16-1-16-1] = 0;
                        if (sd_id128_from_string(de->d_name + q-8-16-1-16-1-32, &seqnum_id) < 0) {
                                free(p);
                                continue;
                        }

                        if (sscanf(de->d_name + q-8-16-1-16, "%16llx-%16llx.journal", &seqnum, &realtime) != 2) {
                                free(p);
                                continue;
                        }

                        have_seqnum = true;

                } else if (endswith(de->d_name, ".journal~")) {
                        unsigned long long tmp;

                        /* Vacuum corrupted files */

                        if (q < 1 + 16 + 1 + 16 + 8 + 1)
                                continue;

                        if (de->d_name[q-1-8-16-1] != '-' ||
                            de->d_name[q-1-8-16-1-16-1] != '@')
                                continue;

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (sscanf(de->d_name + q-1-8-16-1-16, "%16llx-%16llx.journal~", &realtime, &tmp) != 2) {
                                free(p);
                                continue;
                        }

                        have_seqnum = false;
                } else
                        continue;

                if (n_list >= n_allocated) {
                        struct vacuum_info *j;

                        n_allocated = MAX(n_allocated * 2U, 8U);
                        j = realloc(list, n_allocated * sizeof(struct vacuum_info));
                        if (!j) {
                                free(p);
                                r = -ENOMEM;
                                goto finish;
                        }

                        list = j;
                }

                list[n_list].filename = p;
                list[n_list].usage = 512UL * (uint64_t) st.st_blocks;
                list[n_list].seqnum = seqnum;
                list[n_list].realtime = realtime;
                list[n_list].seqnum_id = seqnum_id;
                list[n_list].have_seqnum = have_seqnum;

                sum += list[n_list].usage;

                n_list ++;
        }

        if (n_list > 0)
                qsort(list, n_list, sizeof(struct vacuum_info), vacuum_compare);

        for(i = 0; i < n_list; i++) {
                struct statvfs ss;

                if (fstatvfs(dirfd(d), &ss) < 0) {
                        r = -errno;
                        goto finish;
                }

                if (sum <= max_use &&
                    (uint64_t) ss.f_bavail * (uint64_t) ss.f_bsize >= min_free)
                        break;

                if (unlinkat(dirfd(d), list[i].filename, 0) >= 0) {
                        log_info("Deleted archived journal %s/%s.", directory, list[i].filename);
                        sum -= list[i].usage;
                } else if (errno != ENOENT)
                        log_warning("Failed to delete %s/%s: %m", directory, list[i].filename);
        }

finish:
        for (i = 0; i < n_list; i++)
                free(list[i].filename);

        free(list);

        if (d)
                closedir(d);

        return r;
}
