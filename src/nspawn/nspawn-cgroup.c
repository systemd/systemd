/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <sys/mount.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "nspawn-cgroup.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

int chown_cgroup(pid_t pid, uid_t uid_shift) {
        _cleanup_free_ char *path = NULL, *fs = NULL;
        _cleanup_close_ int fd = -1;
        const char *fn;
        int r;

        r = cg_pid_get_path(NULL, pid, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to get container cgroup path: %m");

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return log_error_errno(r, "Failed to get file system path for container cgroup: %m");

        fd = open(fs, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", fs);

        FOREACH_STRING(fn,
                       ".",
                       "tasks",
                       "notify_on_release",
                       "cgroup.procs",
                       "cgroup.clone_children",
                       "cgroup.controllers",
                       "cgroup.subtree_control",
                       "cgroup.populated")
                if (fchownat(fd, fn, uid_shift, uid_shift, 0) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG :  LOG_WARNING, errno,
                                       "Failed to chown() cgroup file %s, ignoring: %m", fn);

        return 0;
}

int sync_cgroup(pid_t pid, bool unified_requested) {
        _cleanup_free_ char *cgroup = NULL;
        char tree[] = "/tmp/unifiedXXXXXX", pid_string[DECIMAL_STR_MAX(pid) + 1];
        bool undo_mount = false;
        const char *fn;
        int unified, r;

        unified = cg_unified();
        if (unified < 0)
                return log_error_errno(unified, "Failed to determine whether the unified hierachy is used: %m");

        if ((unified > 0) == unified_requested)
                return 0;

        /* When the host uses the legacy cgroup setup, but the
         * container shall use the unified hierarchy, let's make sure
         * we copy the path from the name=systemd hierarchy into the
         * unified hierarchy. Similar for the reverse situation. */

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to get control group of " PID_FMT ": %m", pid);

        /* In order to access the unified hierarchy we need to mount it */
        if (!mkdtemp(tree))
                return log_error_errno(errno, "Failed to generate temporary mount point for unified hierarchy: %m");

        if (unified)
                r = mount("cgroup", tree, "cgroup", MS_NOSUID|MS_NOEXEC|MS_NODEV, "none,name=systemd,xattr");
        else
                r = mount("cgroup", tree, "cgroup", MS_NOSUID|MS_NOEXEC|MS_NODEV, "__DEVEL__sane_behavior");
        if (r < 0) {
                r = log_error_errno(errno, "Failed to mount unified hierarchy: %m");
                goto finish;
        }

        undo_mount = true;

        fn = strjoina(tree, cgroup, "/cgroup.procs");
        (void) mkdir_parents(fn, 0755);

        sprintf(pid_string, PID_FMT, pid);
        r = write_string_file(fn, pid_string, 0);
        if (r < 0)
                log_error_errno(r, "Failed to move process: %m");

finish:
        if (undo_mount)
                (void) umount(tree);

        (void) rmdir(tree);
        return r;
}

int create_subcgroup(pid_t pid, bool unified_requested) {
        _cleanup_free_ char *cgroup = NULL;
        const char *child;
        int unified, r;
        CGroupMask supported;

        /* In the unified hierarchy inner nodes may only only contain
         * subgroups, but not processes. Hence, if we running in the
         * unified hierarchy and the container does the same, and we
         * did not create a scope unit for the container move us and
         * the container into two separate subcgroups. */

        if (!unified_requested)
                return 0;

        unified = cg_unified();
        if (unified < 0)
                return log_error_errno(unified, "Failed to determine whether the unified hierachy is used: %m");
        if (unified == 0)
                return 0;

        r = cg_mask_supported(&supported);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to get our control group: %m");

        child = strjoina(cgroup, "/payload");
        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, child, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s subcgroup: %m", child);

        child = strjoina(cgroup, "/supervisor");
        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, child, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s subcgroup: %m", child);

        /* Try to enable as many controllers as possible for the new payload. */
        (void) cg_enable_everywhere(supported, supported, cgroup);
        return 0;
}
