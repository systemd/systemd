/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#include "util.h"
#include "macro.h"
#include "cgroup-util.h"
#include "cgroup-show.h"

static int compare(const void *a, const void *b) {
        const pid_t *p = a, *q = b;

        if (*p < *q)
                return -1;
        if (*p > *q)
                return 1;
        return 0;
}

static char *get_cgroup_path(const char *name) {

        if (!name)
                return strdup("/cgroup/systemd");

        if (startswith(name, SYSTEMD_CGROUP_CONTROLLER ":"))
                name += sizeof(SYSTEMD_CGROUP_CONTROLLER);

        if (path_startswith(name, "/cgroup"))
                return strdup(name);

        return strappend("/cgroup/systemd/", name);
}

static unsigned ilog10(unsigned long ul) {
        int n = 0;

        while (ul > 0) {
                n++;
                ul /= 10;
        }

        return n;
}

static int show_cgroup_full(const char *path, const char *prefix, unsigned n_columns, bool more) {
        char *fn;
        FILE *f;
        size_t n = 0, n_allocated = 0;
        pid_t *pids = NULL;
        char *p;
        pid_t pid, biggest = 0;
        int r;

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";

        if (!(p = get_cgroup_path(path)))
                return -ENOMEM;

        r = asprintf(&fn, "%s/cgroup.procs", p);
        free(p);

        if (r < 0)
                return -ENOMEM;

        f = fopen(fn, "re");
        free(fn);

        if (!f)
                return -errno;

        while ((r = cg_read_pid(f, &pid)) > 0) {

                if (n >= n_allocated) {
                        pid_t *npids;

                        n_allocated = MAX(16U, n*2U);

                        if (!(npids = realloc(pids, sizeof(pid_t) * n_allocated))) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        pids = npids;
                }

                assert(n < n_allocated);
                pids[n++] = pid;

                if (pid > biggest)
                        biggest = pid;
        }

        if (r < 0)
                goto finish;

        if (n > 0) {
                unsigned i, m;

                /* Filter duplicates */
                m = 0;
                for (i = 0; i < n; i++) {
                        unsigned j;

                        for (j = i+1; j < n; j++)
                                if (pids[i] == pids[j])
                                        break;

                        if (j >= n)
                                pids[m++] = pids[i];
                }
                n = m;

                /* And sort */
                qsort(pids, n, sizeof(pid_t), compare);

                if (n_columns > 8)
                        n_columns -= 8;
                else
                        n_columns = 20;

                for (i = 0; i < n; i++) {
                        char *t = NULL;

                        get_process_cmdline(pids[i], n_columns, &t);

                        printf("%s%s %*lu %s\n",
                               prefix,
                               (more || i < n-1) ? "\342\224\234" : "\342\224\224",
                               ilog10(biggest),
                               (unsigned long) pids[i],
                               strna(t));

                        free(t);
                }
        }

        r = 0;

finish:
        free(pids);

        if (f)
                fclose(f);

        return r;
}

int show_cgroup(const char *path, const char *prefix, unsigned n_columns) {
        return show_cgroup_full(path, prefix, n_columns, false);
}

int show_cgroup_recursive(const char *path, const char *prefix, unsigned n_columns) {
        DIR *d;
        char *last = NULL;
        char *p1 = NULL, *p2 = NULL, *fn = NULL;
        struct dirent *de;
        bool shown_pids = false;
        int r;

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";

        if (!(fn = get_cgroup_path(path)))
                return -ENOMEM;

        if (!(d = opendir(fn))) {
                free(fn);
                return -errno;
        }

        while ((de = readdir(d))) {

                if (de->d_type != DT_DIR)
                        continue;

                if (ignore_file(de->d_name))
                        continue;

                if (!shown_pids) {
                        show_cgroup_full(path, prefix, n_columns, true);
                        shown_pids = true;
                }

                if (last) {
                        printf("%s\342\224\234 %s\n", prefix, file_name_from_path(last));

                        if (!p1)
                                if (!(p1 = strappend(prefix, "\342\224\202 "))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                        show_cgroup_recursive(last, p1, n_columns-2);

                        free(last);
                        last = NULL;
                }

                if (asprintf(&last, "%s/%s", strempty(path), de->d_name) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        if (!shown_pids)
                show_cgroup_full(path, prefix, n_columns, !!last);

        if (last) {
                printf("%s\342\224\224 %s\n", prefix, file_name_from_path(last));

                if (!p2)
                        if (!(p2 = strappend(prefix, "  "))) {
                                r = -ENOMEM;
                                goto finish;
                        }

                show_cgroup_recursive(last, p2, n_columns-2);
        }

        r = 0;

finish:
        free(p1);
        free(p2);
        free(last);
        free(fn);

        closedir(d);

        return r;
}
