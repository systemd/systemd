/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "env-file.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "locale-util.h"
#include "macro.h"
#include "nulstr-util.h"
#include "output-mode.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "xattr-util.h"

static void show_pid_array(
                pid_t pids[],
                size_t n_pids,
                const char *prefix,
                size_t n_columns,
                bool extra,
                bool more,
                OutputFlags flags) {

        size_t i, j, pid_width;

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
                n_columns = SIZE_MAX;
        else {
                if (n_columns > pid_width + 3) /* something like "├─1114784 " */
                        n_columns -= pid_width + 3;
                else
                        n_columns = 20;
        }
        for (i = 0; i < n_pids; i++) {
                _cleanup_free_ char *t = NULL;

                (void) pid_get_cmdline(pids[i], n_columns,
                                       PROCESS_CMDLINE_COMM_FALLBACK | PROCESS_CMDLINE_USE_LOCALE,
                                       &t);

                if (extra)
                        printf("%s%s ", prefix, special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET));
                else
                        printf("%s%s", prefix, special_glyph(((more || i < n_pids-1) ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT)));

                printf("%s%*"PID_PRI" %s%s\n", ansi_grey(), (int) pid_width, pids[i], strna(t), ansi_normal());
        }
}

static int show_cgroup_one_by_path(
                const char *path,
                const char *prefix,
                size_t n_columns,
                bool more,
                OutputFlags flags) {

        _cleanup_free_ pid_t *pids = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        size_t n = 0;
        char *fn;
        int r;

        r = cg_mangle_path(path, &p);
        if (r < 0)
                return r;

        fn = strjoina(p, "/cgroup.procs");
        f = fopen(fn, "re");
        if (!f)
                return -errno;

        for (;;) {
                pid_t pid;

                /* libvirt / qemu uses threaded mode and cgroup.procs cannot be read at the lower levels.
                 * From https://docs.kernel.org/admin-guide/cgroup-v2.html#threads,
                 * “cgroup.procs” in a threaded domain cgroup contains the PIDs of all processes in
                 * the subtree and is not readable in the subtree proper. */
                r = cg_read_pid(f, &pid);
                if (IN_SET(r, 0, -EOPNOTSUPP))
                        break;
                if (r < 0)
                        return r;

                if (!(flags & OUTPUT_KERNEL_THREADS) && pid_is_kernel_thread(pid) > 0)
                        continue;

                if (!GREEDY_REALLOC(pids, n + 1))
                        return -ENOMEM;

                pids[n++] = pid;
        }

        show_pid_array(pids, n, prefix, n_columns, false, more, flags);

        return 0;
}

static int show_cgroup_name(
                const char *path,
                const char *prefix,
                SpecialGlyph glyph,
                OutputFlags flags) {

        uint64_t cgroupid = UINT64_MAX;
        _cleanup_free_ char *b = NULL;
        _cleanup_close_ int fd = -EBADF;
        bool delegate;
        int r;

        fd = open(path, O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY, 0);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open cgroup '%s', ignoring: %m", path);

        r = cg_is_delegated_fd(fd);
        if (r < 0)
                log_debug_errno(r, "Failed to check if cgroup is delegated, ignoring: %m");
        delegate = r > 0;

        if (FLAGS_SET(flags, OUTPUT_CGROUP_ID)) {
                r = cg_fd_get_cgroupid(fd, &cgroupid);
                if (r < 0)
                        log_debug_errno(errno, "Failed to determine cgroup ID of %s, ignoring: %m", path);
        }

        r = path_extract_filename(path, &b);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from cgroup path: %m");

        printf("%s%s%s%s%s",
               prefix, special_glyph(glyph),
               delegate ? ansi_underline() : "",
               cg_unescape(b),
               delegate ? ansi_normal() : "");

        if (delegate)
                printf(" %s%s%s",
                       ansi_highlight(),
                       special_glyph(SPECIAL_GLYPH_ELLIPSIS),
                       ansi_normal());

        if (cgroupid != UINT64_MAX)
                printf(" %s(#%" PRIu64 ")%s", ansi_grey(), cgroupid, ansi_normal());

        printf("\n");

        if (FLAGS_SET(flags, OUTPUT_CGROUP_XATTRS)) {
                _cleanup_free_ char *nl = NULL;

                r = flistxattr_malloc(fd, &nl);
                if (r < 0)
                        log_debug_errno(r, "Failed to enumerate xattrs on '%s', ignoring: %m", path);

                NULSTR_FOREACH(xa, nl) {
                        _cleanup_free_ char *x = NULL, *y = NULL, *buf = NULL;
                        int n;

                        if (!STARTSWITH_SET(xa, "user.", "trusted."))
                                continue;

                        n = fgetxattr_malloc(fd, xa, &buf);
                        if (n < 0) {
                                log_debug_errno(r, "Failed to read xattr '%s' off '%s', ignoring: %m", xa, path);
                                continue;
                        }

                        x = cescape(xa);
                        if (!x)
                                return -ENOMEM;

                        y = cescape_length(buf, n);
                        if (!y)
                                return -ENOMEM;

                        printf("%s%s%s %s%s%s: %s\n",
                               prefix,
                               glyph == SPECIAL_GLYPH_TREE_BRANCH ? special_glyph(SPECIAL_GLYPH_TREE_VERTICAL) : "  ",
                               special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                               ansi_blue(), x, ansi_normal(),
                               y);
                }
        }

        return 0;
}

int show_cgroup_by_path(
                const char *path,
                const char *prefix,
                size_t n_columns,
                OutputFlags flags) {

        _cleanup_free_ char *fn = NULL, *p1 = NULL, *last = NULL, *p2 = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        bool shown_pids = false;
        char *gn = NULL;
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

                k = path_join(fn, gn);
                free(gn);
                if (!k)
                        return -ENOMEM;

                if (!(flags & OUTPUT_SHOW_ALL) && cg_is_empty_recursive(NULL, k) > 0)
                        continue;

                if (!shown_pids) {
                        (void) show_cgroup_one_by_path(path, prefix, n_columns, true, flags);
                        shown_pids = true;
                }

                if (last) {
                        r = show_cgroup_name(last, prefix, SPECIAL_GLYPH_TREE_BRANCH, flags);
                        if (r < 0)
                                return r;

                        if (!p1) {
                                p1 = strjoin(prefix, special_glyph(SPECIAL_GLYPH_TREE_VERTICAL));
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
                (void) show_cgroup_one_by_path(path, prefix, n_columns, !!last, flags);

        if (last) {
                r = show_cgroup_name(last, prefix, SPECIAL_GLYPH_TREE_RIGHT, flags);
                if (r < 0)
                        return r;

                if (!p2) {
                        p2 = strjoin(prefix, "  ");
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
                size_t n_columns,
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
                size_t n_columns,
                const pid_t pids[],
                size_t n_pids,
                OutputFlags flags) {

        _cleanup_free_ pid_t *copy = NULL;
        size_t i, j;
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
                size_t n_columns,
                const pid_t extra_pids[],
                size_t n_extra_pids,
                OutputFlags flags) {

        int r;

        assert(path);

        r = show_cgroup(controller, path, prefix, n_columns, flags);
        if (r < 0)
                return r;

        return show_extra_pids(controller, path, prefix, n_columns, extra_pids, n_extra_pids, flags);
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

        _cleanup_free_ char *root = NULL;
        int r;

        if (machine) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_free_ char *unit = NULL;
                const char *m;

                if (!hostname_is_valid(machine, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine name is not valid: %s", machine);

                m = strjoina("/run/systemd/machines/", machine);
                r = parse_env_file(NULL, m, "SCOPE", &unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to load machine data: %m");

                r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, RUNTIME_SCOPE_SYSTEM, &bus);
                if (r < 0)
                        return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL);

                r = show_cgroup_get_unit_path_and_warn(bus, unit, &root);
                if (r < 0)
                        return r;
        } else {
                r = cg_get_root_path(&root);
                if (r == -ENOMEDIUM)
                        return log_error_errno(r, "Failed to get root control group path.\n"
                                                  "No cgroup filesystem mounted on /sys/fs/cgroup");
                if (r < 0)
                        return log_error_errno(r, "Failed to get root control group path: %m");
        }

        if (prefix) {
                char *t;

                t = path_join(root, prefix);
                if (!t)
                        return log_oom();

                *ret = t;
        } else
                *ret = TAKE_PTR(root);

        return 0;
}
