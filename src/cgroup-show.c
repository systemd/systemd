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

#include "util.h"
#include "macro.h"
#include "cgroup-show.h"

static int compare(const void *a, const void *b) {
        const pid_t *p = a, *q = b;

        if (*p < *q)
                return -1;
        if (*p > *q)
                return 1;
        return 0;
}

void show_cgroup(const char *name, const char *prefix, unsigned columns) {
        char *fn;
        FILE *f;
        size_t n = 0, n_allocated = 0;
        pid_t *pids = NULL;

        if (!startswith(name, "name=systemd:"))
                return;

        if (asprintf(&fn, "/cgroup/systemd/%s/cgroup.procs", name + 13) < 0) {
                log_error("Out of memory");
                return;
        }

        f = fopen(fn, "r");
        free(fn);

        if (!f)
                return;

        while (!feof(f)) {
                unsigned long ul;

                if (fscanf(f, "%lu", &ul) != 1)
                        break;

                if (ul <= 0)
                        continue;

                if (n >= n_allocated) {
                        pid_t *npids;

                        n_allocated = MAX(16U, n*2U);

                        if (!(npids = realloc(pids, sizeof(pid_t) * n_allocated))) {
                                log_error("Out of memory");
                                goto finish;
                        }

                        pids = npids;
                }

                assert(n < n_allocated);
                pids[n++] = (pid_t) ul;
        }

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

                if (!prefix)
                        prefix = "";

                if (columns > 8)
                        columns -= 8;
                else
                        columns = 20;

                printf("%s\342\224\202\n", prefix);

                for (i = 0; i < n; i++) {
                        char *t = NULL;

                        get_process_cmdline(pids[i], columns, &t);

                        printf("%s%s %5lu %s\n",
                               prefix,
                               i < n-1 ? "\342\224\234" : "\342\224\224",
                               (unsigned long) pids[i], strna(t));

                        free(t);
                }
        }

finish:
        free(pids);

        if (f)
                fclose(f);
}
