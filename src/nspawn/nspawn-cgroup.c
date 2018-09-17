/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/mount.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "mount-util.h"
#include "nspawn-cgroup.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int chown_cgroup_path(const char *path, uid_t uid_shift) {
        _cleanup_close_ int fd = -1;
        const char *fn;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        FOREACH_STRING(fn,
                       ".",
                       "cgroup.clone_children",
                       "cgroup.controllers",
                       "cgroup.events",
                       "cgroup.procs",
                       "cgroup.stat",
                       "cgroup.subtree_control",
                       "cgroup.threads",
                       "notify_on_release",
                       "tasks")
                if (fchownat(fd, fn, uid_shift, uid_shift, 0) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG :  LOG_WARNING, errno,
                                       "Failed to chown \"%s/%s\", ignoring: %m", path, fn);

        return 0;
}

int chown_cgroup(pid_t pid, CGroupUnified unified_requested, uid_t uid_shift) {
        _cleanup_free_ char *path = NULL, *fs = NULL;
        int r;

        r = cg_pid_get_path(NULL, pid, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to get container cgroup path: %m");

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return log_error_errno(r, "Failed to get file system path for container cgroup: %m");

        r = chown_cgroup_path(fs, uid_shift);
        if (r < 0)
                return log_error_errno(r, "Failed to chown() cgroup %s: %m", fs);

        if (unified_requested == CGROUP_UNIFIED_SYSTEMD || (unified_requested == CGROUP_UNIFIED_NONE && cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0)) {
                _cleanup_free_ char *lfs = NULL;
                /* Always propagate access rights from unified to legacy controller */

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path, NULL, &lfs);
                if (r < 0)
                        return log_error_errno(r, "Failed to get file system path for container cgroup: %m");

                r = chown_cgroup_path(lfs, uid_shift);
                if (r < 0)
                        return log_error_errno(r, "Failed to chown() cgroup %s: %m", lfs);
        }

        return 0;
}

int sync_cgroup(pid_t pid, CGroupUnified unified_requested, uid_t arg_uid_shift) {
        _cleanup_free_ char *cgroup = NULL;
        char tree[] = "/tmp/unifiedXXXXXX", pid_string[DECIMAL_STR_MAX(pid) + 1];
        bool undo_mount = false;
        const char *fn;
        int r, unified_controller;

        unified_controller = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (unified_controller < 0)
                return log_error_errno(unified_controller, "Failed to determine whether the systemd hierarchy is unified: %m");
        if ((unified_controller > 0) == (unified_requested >= CGROUP_UNIFIED_SYSTEMD))
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

        if (unified_controller > 0)
                r = mount_verbose(LOG_ERR, "cgroup", tree, "cgroup",
                                  MS_NOSUID|MS_NOEXEC|MS_NODEV, "none,name=systemd,xattr");
        else
                r = mount_verbose(LOG_ERR, "cgroup", tree, "cgroup2",
                                  MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
        if (r < 0)
                goto finish;

        undo_mount = true;

        /* If nspawn dies abruptly the cgroup hierarchy created below
         * its unit isn't cleaned up. So, let's remove it
         * https://github.com/systemd/systemd/pull/4223#issuecomment-252519810 */
        fn = strjoina(tree, cgroup);
        (void) rm_rf(fn, REMOVE_ROOT|REMOVE_ONLY_DIRECTORIES);

        fn = strjoina(tree, cgroup, "/cgroup.procs");
        (void) mkdir_parents(fn, 0755);

        sprintf(pid_string, PID_FMT, pid);
        r = write_string_file(fn, pid_string, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to move process: %m");
                goto finish;
        }

        fn = strjoina(tree, cgroup);
        r = chown_cgroup_path(fn, arg_uid_shift);
        if (r < 0)
                log_error_errno(r, "Failed to chown() cgroup %s: %m", fn);
finish:
        if (undo_mount)
                (void) umount_verbose(tree);

        (void) rmdir(tree);
        return r;
}

int create_subcgroup(pid_t pid, bool keep_unit, CGroupUnified unified_requested) {
        _cleanup_free_ char *cgroup = NULL;
        CGroupMask supported;
        const char *payload;
        int r;

        assert(pid > 1);

        /* In the unified hierarchy inner nodes may only contain subgroups, but not processes. Hence, if we running in
         * the unified hierarchy and the container does the same, and we did not create a scope unit for the container
         * move us and the container into two separate subcgroups.
         *
         * Moreover, container payloads such as systemd try to manage the cgroup they run in in full (i.e. including
         * its attributes), while the host systemd will only delegate cgroups for children of the cgroup created for a
         * delegation unit, instead of the cgroup itself. This means, if we'd pass on the cgroup allocated from the
         * host systemd directly to the payload, the host and payload systemd might fight for the cgroup
         * attributes. Hence, let's insert an intermediary cgroup to cover that case too.
         *
         * Note that we only bother with the main hierarchy here, not with any secondary ones. On the unified setup
         * that's fine because there's only one hiearchy anyway and controllers are enabled directly on it. On the
         * legacy setup, this is fine too, since delegation of controllers is generally not safe there, hence we won't
         * do it. */

        r = cg_mask_supported(&supported);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        if (keep_unit)
                r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        else
                r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to get our control group: %m");

        payload = strjoina(cgroup, "/payload");
        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, payload, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s subcgroup: %m", payload);

        if (keep_unit) {
                const char *supervisor;

                supervisor = strjoina(cgroup, "/supervisor");
                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, supervisor, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to create %s subcgroup: %m", supervisor);
        }

        /* Try to enable as many controllers as possible for the new payload. */
        (void) cg_enable_everywhere(supported, supported, cgroup);
        return 0;
}
