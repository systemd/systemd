/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "locale-util.h"
#include "macro.h"
#include "output-mode.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "unit-name.h"

static void show_pid_array(
                pid_t pids[],
                unsigned n_pids,
                const char *prefix,
                unsigned n_columns,
                bool extra,
                bool more,
                OutputFlags flags) {

        unsigned i, j, pid_width;

        if (n_pids == 0)
                return;

        typesafe_qsort(pids, n_pids, pid_compare_func);

        /* Filter duplicates */
        for (j = 0, i = 1; i < n_pids; i++) {
                if (pids[i] == pids[j])
                        continue;
                pids[++j] = pids[i];
        }
        n_pids = j + 1;
        pid_width = DECIMAL_STR_WIDTH(pids[j]);

        if (flags & OUTPUT_FULL_WIDTH)
                n_columns = 0;
        else {
                if (n_columns > pid_width+2)
                        n_columns -= pid_width+2;
                else
                        n_columns = 20;
        }
        for (i = 0; i < n_pids; i++) {
                _cleanup_free_ char *t = NULL;

                (void) get_process_cmdline(pids[i], n_columns, true, &t);

                if (extra)
                        printf("%s%s ", prefix, special_glyph(TRIANGULAR_BULLET));
                else
                        printf("%s%s", prefix, special_glyph(((more || i < n_pids-1) ? TREE_BRANCH : TREE_RIGHT)));

                printf("%*"PID_PRI" %s\n", pid_width, pids[i], strna(t));
        }
}

static int show_cgroup_one_by_path(
                const char *path,
                const char *prefix,
                unsigned n_columns,
                bool more,
                OutputFlags flags) {

        char *fn;
        _cleanup_fclose_ FILE *f = NULL;
        size_t n = 0, n_allocated = 0;
        _cleanup_free_ pid_t *pids = NULL;
        _cleanup_free_ char *p = NULL;
        pid_t pid;
        int r;

        r = cg_mangle_path(path, &p);
        if (r < 0)
                return r;

        fn = strjoina(p, "/cgroup.procs");
        f = fopen(fn, "re");
        if (!f)
                return -errno;

        while ((r = cg_read_pid(f, &pid)) > 0) {

                if (!(flags & OUTPUT_KERNEL_THREADS) && is_kernel_thread(pid) > 0)
                        continue;

                if (!GREEDY_REALLOC(pids, n_allocated, n + 1))
                        return -ENOMEM;

                assert(n < n_allocated);
                pids[n++] = pid;
        }

        if (r < 0)
                return r;

        show_pid_array(pids, n, prefix, n_columns, false, more, flags);

        return 0;
}

int show_cgroup_by_path(
                const char *path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        _cleanup_free_ char *fn = NULL, *p1 = NULL, *last = NULL, *p2 = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        char *gn = NULL;
        bool shown_pids = false;
        int r;

        assert(path);

        if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        r = cg_mangle_path(path, &fn);
        if (r < 0)
                return r;

        d = opendir(fn);
        if (!d)
                return -errno;

        while ((r = cg_read_subgroup(d, &gn)) > 0) {
                _cleanup_free_ char *k = NULL;

                k = strjoin(fn, "/", gn);
                free(gn);
                if (!k)
                        return -ENOMEM;

                if (!(flags & OUTPUT_SHOW_ALL) && cg_is_empty_recursive(NULL, k) > 0)
                        continue;

                if (!shown_pids) {
                        show_cgroup_one_by_path(path, prefix, n_columns, true, flags);
                        shown_pids = true;
                }

                if (last) {
                        printf("%s%s%s\n", prefix, special_glyph(TREE_BRANCH), cg_unescape(basename(last)));

                        if (!p1) {
                                p1 = strappend(prefix, special_glyph(TREE_VERTICAL));
                                if (!p1)
                                        return -ENOMEM;
                        }

                        show_cgroup_by_path(last, p1, n_columns-2, flags);
                        free(last);
                }

                last = TAKE_PTR(k);
        }

        if (r < 0)
                return r;

        if (!shown_pids)
                show_cgroup_one_by_path(path, prefix, n_columns, !!last, flags);

        if (last) {
                printf("%s%s%s\n", prefix, special_glyph(TREE_RIGHT), cg_unescape(basename(last)));

                if (!p2) {
                        p2 = strappend(prefix, "  ");
                        if (!p2)
                                return -ENOMEM;
                }

                show_cgroup_by_path(last, p2, n_columns-2, flags);
        }

        return 0;
}

int show_cgroup(const char *controller,
                const char *path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(path);

        r = cg_get_path(controller, path, NULL, &p);
        if (r < 0)
                return r;

        return show_cgroup_by_path(p, prefix, n_columns, flags);
}

static int show_extra_pids(
                const char *controller,
                const char *path,
                const char *prefix,
                unsigned n_columns,
                const pid_t pids[],
                unsigned n_pids,
                OutputFlags flags) {

        _cleanup_free_ pid_t *copy = NULL;
        unsigned i, j;
        int r;

        assert(path);

        if (n_pids <= 0)
                return 0;

        if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        copy = new(pid_t, n_pids);
        if (!copy)
                return -ENOMEM;

        for (i = 0, j = 0; i < n_pids; i++) {
                _cleanup_free_ char *k = NULL;

                r = cg_pid_get_path(controller, pids[i], &k);
                if (r < 0)
                        return r;

                if (path_startswith(k, path))
                        continue;

                copy[j++] = pids[i];
        }

        show_pid_array(copy, j, prefix, n_columns, true, false, flags);

        return 0;
}

int show_cgroup_and_extra(
                const char *controller,
                const char *path,
                const char *prefix,
                unsigned n_columns,
                const pid_t extra_pids[],
                unsigned n_extra_pids,
                OutputFlags flags) {

        int r;

        assert(path);

        r = show_cgroup(controller, path, prefix, n_columns, flags);
        if (r < 0)
                return r;

        return show_extra_pids(controller, path, prefix, n_columns, extra_pids, n_extra_pids, flags);
}

int show_cgroup_and_extra_by_spec(
                const char *spec,
                const char *prefix,
                unsigned n_columns,
                const pid_t extra_pids[],
                unsigned n_extra_pids,
                OutputFlags flags) {

        _cleanup_free_ char *controller = NULL, *path = NULL;
        int r;

        assert(spec);

        r = cg_split_spec(spec, &controller, &path);
        if (r < 0)
                return r;

        return show_cgroup_and_extra(controller, path, prefix, n_columns, extra_pids, n_extra_pids, flags);
}

int show_cgroup_get_unit_path_and_warn(
                sd_bus *bus,
                const char *unit,
                char **ret) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        unit_dbus_interface_from_name(unit),
                        "ControlGroup",
                        &error,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to query unit control group path: %s",
                                       bus_error_message(&error, r));

        return 0;
}

int show_cgroup_get_path_and_warn(
                const char *machine,
                const char *prefix,
                char **ret) {

        int r;
        _cleanup_free_ char *root = NULL;

        if (machine) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_free_ char *unit = NULL;
                const char *m;

                m = strjoina("/run/systemd/machines/", machine);
                r = parse_env_file(NULL, m, NEWLINE, "SCOPE", &unit, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to load machine data: %m");

                r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, false, &bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to create bus connection: %m");

                r = show_cgroup_get_unit_path_and_warn(bus, unit, &root);
                if (r < 0)
                        return r;
        } else {
                r = cg_get_root_path(&root);
                if (r == -ENOMEDIUM)
                        return log_error_errno(r, "Failed to get root control group path.\n"
                                                  "No cgroup filesystem mounted on /sys/fs/cgroup");
                else if (r < 0)
                        return log_error_errno(r, "Failed to get root control group path: %m");
        }

        if (prefix) {
                char *t;

                t = strjoin(root, prefix);
                if (!t)
                        return log_oom();

                *ret = t;
        } else
                *ret = TAKE_PTR(root);

        return 0;
}
