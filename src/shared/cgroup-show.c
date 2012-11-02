/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#include "util.h"
#include "macro.h"
#include "path-util.h"
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

static unsigned ilog10(unsigned long ul) {
        int n = 0;

        while (ul > 0) {
                n++;
                ul /= 10;
        }

        return n;
}

static void show_pid_array(int pids[], unsigned n_pids, const char *prefix, unsigned n_columns, bool extra, bool more, bool kernel_threads) {
        unsigned i, m, pid_width;
        pid_t biggest = 0;

        /* Filter duplicates */
        m = 0;
        for (i = 0; i < n_pids; i++) {
                unsigned j;

                if (pids[i] > biggest)
                        biggest = pids[i];

                for (j = i+1; j < n_pids; j++)
                        if (pids[i] == pids[j])
                                break;

                if (j >= n_pids)
                        pids[m++] = pids[i];
        }
        n_pids = m;
        pid_width = ilog10(biggest);

        /* And sort */
        qsort(pids, n_pids, sizeof(pid_t), compare);

        if (n_columns > pid_width+2)
                n_columns -= pid_width+2;
        else
                n_columns = 20;

        for (i = 0; i < n_pids; i++) {
                char *t = NULL;

                get_process_cmdline(pids[i], n_columns, true, &t);

                printf("%s%s %*lu %s\n",
                       prefix,
                       draw_special_char(extra ? DRAW_TRIANGULAR_BULLET :
                                         ((more || i < n_pids-1) ? DRAW_BOX_VERT_AND_RIGHT : DRAW_BOX_UP_AND_RIGHT)),
                       pid_width,
                       (unsigned long) pids[i],
                       strna(t));

                free(t);
        }
}


static int show_cgroup_one_by_path(const char *path, const char *prefix, unsigned n_columns, bool more, bool kernel_threads) {
        char *fn;
        FILE *f;
        size_t n = 0, n_allocated = 0;
        pid_t *pids = NULL;
        char *p;
        pid_t pid;
        int r;

        r = cg_fix_path(path, &p);
        if (r < 0)
                return r;

        r = asprintf(&fn, "%s/cgroup.procs", p);
        free(p);
        if (r < 0)
                return -ENOMEM;

        f = fopen(fn, "re");
        free(fn);
        if (!f)
                return -errno;

        while ((r = cg_read_pid(f, &pid)) > 0) {

                if (!kernel_threads && is_kernel_thread(pid) > 0)
                        continue;

                if (n >= n_allocated) {
                        pid_t *npids;

                        n_allocated = MAX(16U, n*2U);

                        npids = realloc(pids, sizeof(pid_t) * n_allocated);
                        if (!npids) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        pids = npids;
                }

                assert(n < n_allocated);
                pids[n++] = pid;
        }

        if (r < 0)
                goto finish;

        if (n > 0)
                show_pid_array(pids, n, prefix, n_columns, false, more, kernel_threads);

        r = 0;

finish:
        free(pids);

        if (f)
                fclose(f);

        return r;
}

int show_cgroup_by_path(const char *path, const char *prefix, unsigned n_columns, bool kernel_threads, bool all) {
        DIR *d;
        char *last = NULL;
        char *p1 = NULL, *p2 = NULL, *fn = NULL, *gn = NULL;
        bool shown_pids = false;
        int r;

        assert(path);

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";

        r = cg_fix_path(path, &fn);
        if (r < 0)
                return r;

        d = opendir(fn);
        if (!d) {
                free(fn);
                return -errno;
        }

        while ((r = cg_read_subgroup(d, &gn)) > 0) {
                char *k;

                r = asprintf(&k, "%s/%s", fn, gn);
                free(gn);
                if (r < 0) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!all && cg_is_empty_recursive(NULL, k, false) > 0) {
                        free(k);
                        continue;
                }

                if (!shown_pids) {
                        show_cgroup_one_by_path(path, prefix, n_columns, true, kernel_threads);
                        shown_pids = true;
                }

                if (last) {
                        printf("%s%s %s\n", prefix, draw_special_char(DRAW_BOX_VERT_AND_RIGHT),
                                            path_get_file_name(last));

                        if (!p1) {
                                p1 = strjoin(prefix, draw_special_char(DRAW_BOX_VERT), " ", NULL);
                                if (!p1) {
                                        free(k);
                                        r = -ENOMEM;
                                        goto finish;
                                }
                        }

                        show_cgroup_by_path(last, p1, n_columns-2, kernel_threads, all);
                        free(last);
                }

                last = k;
        }

        if (r < 0)
                goto finish;

        if (!shown_pids)
                show_cgroup_one_by_path(path, prefix, n_columns, !!last, kernel_threads);

        if (last) {
                printf("%s%s %s\n", prefix, draw_special_char(DRAW_BOX_UP_AND_RIGHT),
                                    path_get_file_name(last));

                if (!p2) {
                        p2 = strappend(prefix, "  ");
                        if (!p2) {
                                r = -ENOMEM;
                                goto finish;
                        }
                }

                show_cgroup_by_path(last, p2, n_columns-2, kernel_threads, all);
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

int show_cgroup(const char *controller, const char *path, const char *prefix, unsigned n_columns, bool kernel_threads, bool all) {
        char *p;
        int r;

        assert(controller);
        assert(path);

        r = cg_get_path(controller, path, NULL, &p);
        if (r < 0)
                return r;

        r = show_cgroup_by_path(p, prefix, n_columns, kernel_threads, all);
        free(p);

        return r;
}

static int show_extra_pids(const char *controller, const char *path, const char *prefix, unsigned n_columns, const pid_t pids[], unsigned n_pids) {
        pid_t *copy;
        unsigned i, j;
        int r;

        assert(controller);
        assert(path);

        if (n_pids <= 0)
                return 0;

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";

        copy = new(pid_t, n_pids);
        if (!copy)
                return -ENOMEM;

        for (i = 0, j = 0; i < n_pids; i++) {
                char *k;

                r = cg_get_by_pid(controller, pids[i], &k);
                if (r < 0) {
                        free(copy);
                        return r;
                }

                if (path_startswith(k, path))
                        continue;

                copy[j++] = pids[i];
        }

        show_pid_array(copy, j, prefix, n_columns, true, false, false);

        free(copy);
        return 0;
}

int show_cgroup_and_extra(const char *controller, const char *path, const char *prefix, unsigned n_columns, bool kernel_threads, bool all, const pid_t extra_pids[], unsigned n_extra_pids) {
        int r;

        assert(controller);
        assert(path);

        r = show_cgroup(controller, path, prefix, n_columns, kernel_threads, all);
        if (r < 0)
                return r;

        return show_extra_pids(controller, path, prefix, n_columns, extra_pids, n_extra_pids);
}

int show_cgroup_and_extra_by_spec(const char *spec, const char *prefix, unsigned n_columns, bool kernel_threads, bool all, const pid_t extra_pids[], unsigned n_extra_pids) {
        int r;
        char *controller, *path;

        assert(spec);

        r = cg_split_spec(spec, &controller, &path);
        if (r < 0)
                return r;

        r = show_cgroup_and_extra(controller, path, prefix, n_columns, kernel_threads, all, extra_pids, n_extra_pids);
        free(controller);
        free(path);

        return r;
}
