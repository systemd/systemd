/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nspawn-cgroup.h"
#include "nspawn-mount.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static int chown_cgroup_path(const char *path, uid_t uid_shift) {
        _cleanup_close_ int fd = -EBADF;

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
                       "memory.oom.group",
                       "memory.reclaim",
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

int sync_cgroup(pid_t pid, CGroupUnified unified_requested, uid_t uid_shift) {
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
                r = mount_nofollow_verbose(LOG_ERR, "cgroup", tree, "cgroup",
                                           MS_NOSUID|MS_NOEXEC|MS_NODEV, "none,name=systemd,xattr");
        else
                r = mount_nofollow_verbose(LOG_ERR, "cgroup", tree, "cgroup2",
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

        sprintf(pid_string, PID_FMT, pid);
        r = write_string_file(fn, pid_string, WRITE_STRING_FILE_DISABLE_BUFFER|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0) {
                log_error_errno(r, "Failed to move process: %m");
                goto finish;
        }

        fn = strjoina(tree, cgroup);
        r = chown_cgroup_path(fn, uid_shift);
        if (r < 0)
                log_error_errno(r, "Failed to chown() cgroup %s: %m", fn);
finish:
        if (undo_mount)
                (void) umount_verbose(LOG_ERR, tree, UMOUNT_NOFOLLOW);

        (void) rmdir(tree);
        return r;
}

int create_subcgroup(pid_t pid, bool keep_unit, CGroupUnified unified_requested) {
        _cleanup_free_ char *cgroup = NULL, *payload = NULL;
        CGroupMask supported;
        char *e;
        int r;

        assert(pid > 1);

        /* In the unified hierarchy inner nodes may only contain subgroups, but not processes. Hence, if we running in
         * the unified hierarchy and the container does the same, and we did not create a scope unit for the container
         * move us and the container into two separate subcgroups.
         *
         * Moreover, container payloads such as systemd try to manage the cgroup they run in full (i.e. including
         * its attributes), while the host systemd will only delegate cgroups for children of the cgroup created for a
         * delegation unit, instead of the cgroup itself. This means, if we'd pass on the cgroup allocated from the
         * host systemd directly to the payload, the host and payload systemd might fight for the cgroup
         * attributes. Hence, let's insert an intermediary cgroup to cover that case too.
         *
         * Note that we only bother with the main hierarchy here, not with any secondary ones. On the unified setup
         * that's fine because there's only one hierarchy anyway and controllers are enabled directly on it. On the
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

        /* If the service manager already placed us in the supervisor cgroup, let's handle that. */
        e = endswith(cgroup, "/supervisor");
        if (e)
                *e = 0; /* chop off, we want the main path delegated to us */

        payload = path_join(cgroup, "payload");
        if (!payload)
                return log_oom();

        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, payload, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s subcgroup: %m", payload);

        if (keep_unit) {
                _cleanup_free_ char *supervisor = NULL;

                supervisor = path_join(cgroup, "supervisor");
                if (!supervisor)
                        return log_oom();

                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, supervisor, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to create %s subcgroup: %m", supervisor);
        }

        /* Try to enable as many controllers as possible for the new payload. */
        (void) cg_enable_everywhere(supported, supported, cgroup, NULL);
        return 0;
}

/* Retrieve existing subsystems. This function is called in a new cgroup
 * namespace.
 */
static int get_process_controllers(Set **ret) {
        _cleanup_set_free_ Set *controllers = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(ret);

        f = fopen("/proc/self/cgroup", "re");
        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *e, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                l = strchr(line, ':');
                if (!l)
                        continue;

                l++;
                e = strchr(l, ':');
                if (!e)
                        continue;

                *e = 0;

                if (STR_IN_SET(l, "", "name=systemd", "name=unified"))
                        continue;

                r = set_put_strdup(&controllers, l);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(controllers);

        return 0;
}

static int mount_legacy_cgroup_hierarchy(
                const char *dest,
                const char *controller,
                const char *hierarchy,
                bool read_only) {

        const char *to, *fstype, *opts;
        int r;

        to = strjoina(strempty(dest), "/sys/fs/cgroup/", hierarchy);

        r = path_is_mount_point(to, dest, 0);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", to);
        if (r > 0)
                return 0;

        (void) mkdir_p(to, 0755);

        /* The superblock mount options of the mount point need to be
         * identical to the hosts', and hence writable... */
        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER_HYBRID)) {
                fstype = "cgroup2";
                opts = NULL;
        } else if (streq(controller, SYSTEMD_CGROUP_CONTROLLER_LEGACY)) {
                fstype = "cgroup";
                opts = "none,name=systemd,xattr";
        } else {
                fstype = "cgroup";
                opts = controller;
        }

        r = mount_nofollow_verbose(LOG_ERR, "cgroup", to, fstype, MS_NOSUID|MS_NOEXEC|MS_NODEV, opts);
        if (r < 0)
                return r;

        /* ... hence let's only make the bind mount read-only, not the superblock. */
        if (read_only) {
                r = mount_nofollow_verbose(LOG_ERR, NULL, to, NULL,
                                           MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL);
                if (r < 0)
                        return r;
        }

        return 1;
}

/* Mount a legacy cgroup hierarchy when cgroup namespaces are supported. */
static int mount_legacy_cgns_supported(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_set_free_ Set *controllers = NULL;
        const char *cgroup_root = "/sys/fs/cgroup", *c;
        int r;

        (void) mkdir_p(cgroup_root, 0755);

        /* Mount a tmpfs to /sys/fs/cgroup if it's not mounted there yet. */
        r = path_is_mount_point(cgroup_root, dest, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if /sys/fs/cgroup is already mounted: %m");
        if (r == 0) {
                _cleanup_free_ char *options = NULL;

                /* When cgroup namespaces are enabled and user namespaces are
                 * used then the mount of the cgroupfs is done *inside* the new
                 * user namespace. We're root in the new user namespace and the
                 * kernel will happily translate our uid/gid to the correct
                 * uid/gid as seen from e.g. /proc/1/mountinfo. So we simply
                 * pass uid 0 and not uid_shift to tmpfs_patch_options().
                 */
                r = tmpfs_patch_options("mode=0755" TMPFS_LIMITS_SYS_FS_CGROUP, 0, selinux_apifs_context, &options);
                if (r < 0)
                        return log_oom();

                r = mount_nofollow_verbose(LOG_ERR, "tmpfs", cgroup_root, "tmpfs",
                                           MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, options);
                if (r < 0)
                        return r;
        }

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                goto skip_controllers;

        r = get_process_controllers(&controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ const char *controller = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                r = mount_legacy_cgroup_hierarchy("", controller, controller, !userns);
                if (r < 0)
                        return r;

                /* When multiple hierarchies are co-mounted, make their
                 * constituting individual hierarchies a symlink to the
                 * co-mount.
                 */
                c = controller;
                for (;;) {
                        _cleanup_free_ char *target = NULL, *tok = NULL;

                        r = extract_first_word(&c, &tok, ",", 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract co-mounted cgroup controller: %m");
                        if (r == 0)
                                break;

                        if (streq(controller, tok))
                                break;

                        target = path_join("/sys/fs/cgroup/", tok);
                        if (!target)
                                return log_oom();

                        r = symlink_idempotent(controller, target, false);
                        if (r == -EINVAL)
                                return log_error_errno(r, "Invalid existing symlink for combined hierarchy: %m");
                        if (r < 0)
                                return log_error_errno(r, "Failed to create symlink for combined hierarchy: %m");
                }
        }

skip_controllers:
        if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                r = mount_legacy_cgroup_hierarchy("", SYSTEMD_CGROUP_CONTROLLER_HYBRID, "unified", false);
                if (r < 0)
                        return r;
        }

        r = mount_legacy_cgroup_hierarchy("", SYSTEMD_CGROUP_CONTROLLER_LEGACY, "systemd", false);
        if (r < 0)
                return r;

        if (!userns)
                return mount_nofollow_verbose(LOG_ERR, NULL, cgroup_root, NULL,
                                              MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY,
                                              "mode=0755");

        return 0;
}

/* Mount legacy cgroup hierarchy when cgroup namespaces are unsupported. */
static int mount_legacy_cgns_unsupported(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_set_free_ Set *controllers = NULL;
        const char *cgroup_root;
        int r;

        cgroup_root = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(cgroup_root, 0755);

        /* Mount a tmpfs to /sys/fs/cgroup if it's not mounted there yet. */
        r = path_is_mount_point(cgroup_root, dest, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if /sys/fs/cgroup is already mounted: %m");
        if (r == 0) {
                _cleanup_free_ char *options = NULL;

                r = tmpfs_patch_options("mode=0755" TMPFS_LIMITS_SYS_FS_CGROUP,
                                        uid_shift == 0 ? UID_INVALID : uid_shift,
                                        selinux_apifs_context,
                                        &options);
                if (r < 0)
                        return log_oom();

                r = mount_nofollow_verbose(LOG_ERR, "tmpfs", cgroup_root, "tmpfs",
                                           MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, options);
                if (r < 0)
                        return r;
        }

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                goto skip_controllers;

        r = cg_kernel_controllers(&controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ char *controller = NULL, *origin = NULL, *combined = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                origin = path_join("/sys/fs/cgroup/", controller);
                if (!origin)
                        return log_oom();

                r = readlink_malloc(origin, &combined);
                if (r == -EINVAL) {
                        /* Not a symbolic link, but directly a single cgroup hierarchy */

                        r = mount_legacy_cgroup_hierarchy(dest, controller, controller, true);
                        if (r < 0)
                                return r;

                } else if (r < 0)
                        return log_error_errno(r, "Failed to read link %s: %m", origin);
                else {
                        _cleanup_free_ char *target = NULL;

                        target = path_join(dest, origin);
                        if (!target)
                                return log_oom();

                        /* A symbolic link, a combination of controllers in one hierarchy */

                        if (!filename_is_valid(combined)) {
                                log_warning("Ignoring invalid combined hierarchy %s.", combined);
                                continue;
                        }

                        r = mount_legacy_cgroup_hierarchy(dest, combined, combined, true);
                        if (r < 0)
                                return r;

                        r = symlink_idempotent(combined, target, false);
                        if (r == -EINVAL)
                                return log_error_errno(r, "Invalid existing symlink for combined hierarchy: %m");
                        if (r < 0)
                                return log_error_errno(r, "Failed to create symlink for combined hierarchy: %m");
                }
        }

skip_controllers:
        if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                r = mount_legacy_cgroup_hierarchy(dest, SYSTEMD_CGROUP_CONTROLLER_HYBRID, "unified", false);
                if (r < 0)
                        return r;
        }

        r = mount_legacy_cgroup_hierarchy(dest, SYSTEMD_CGROUP_CONTROLLER_LEGACY, "systemd", false);
        if (r < 0)
                return r;

        return mount_nofollow_verbose(LOG_ERR, NULL, cgroup_root, NULL,
                                      MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY,
                                      "mode=0755");
}

static int mount_unified_cgroups(const char *dest) {
        const char *p;
        int r;

        assert(dest);

        p = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(p, 0755);

        r = path_is_mount_point(p, dest, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", p);
        if (r > 0) {
                p = prefix_roota(dest, "/sys/fs/cgroup/cgroup.procs");
                if (access(p, F_OK) >= 0)
                        return 0;
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine if mount point %s contains the unified cgroup hierarchy: %m", p);

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s is already mounted but not a unified cgroup hierarchy. Refusing.", p);
        }

        return mount_nofollow_verbose(LOG_ERR, "cgroup", p, "cgroup2", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
}

int mount_cgroups(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context,
                bool use_cgns) {

        if (unified_requested >= CGROUP_UNIFIED_ALL)
                return mount_unified_cgroups(dest);
        if (use_cgns)
                return mount_legacy_cgns_supported(dest, unified_requested, userns, uid_shift, uid_range, selinux_apifs_context);

        return mount_legacy_cgns_unsupported(dest, unified_requested, userns, uid_shift, uid_range, selinux_apifs_context);
}

static int mount_systemd_cgroup_writable_one(const char *root, const char *own) {
        int r;

        assert(root);
        assert(own);

        /* Make our own cgroup a (writable) bind mount */
        r = mount_nofollow_verbose(LOG_ERR, own, own, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        /* And then remount the systemd cgroup root read-only */
        return mount_nofollow_verbose(LOG_ERR, NULL, root, NULL,
                                      MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL);
}

int mount_systemd_cgroup_writable(
                const char *dest,
                CGroupUnified unified_requested) {

        _cleanup_free_ char *own_cgroup_path = NULL;
        const char *root, *own;
        int r;

        assert(dest);

        r = cg_pid_get_path(NULL, 0, &own_cgroup_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine our own cgroup path: %m");

        /* If we are living in the top-level, then there's nothing to do... */
        if (path_equal(own_cgroup_path, "/"))
                return 0;

        if (unified_requested >= CGROUP_UNIFIED_ALL) {

                root = prefix_roota(dest, "/sys/fs/cgroup");
                own = strjoina(root, own_cgroup_path);

        } else {

                if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                        root = prefix_roota(dest, "/sys/fs/cgroup/unified");
                        own = strjoina(root, own_cgroup_path);

                        r = mount_systemd_cgroup_writable_one(root, own);
                        if (r < 0)
                                return r;
                }

                root = prefix_roota(dest, "/sys/fs/cgroup/systemd");
                own = strjoina(root, own_cgroup_path);
        }

        return mount_systemd_cgroup_writable_one(root, own);
}
