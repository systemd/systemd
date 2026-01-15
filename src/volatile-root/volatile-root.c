/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chase.h"
#include "devnum-util.h"
#include "escape.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "volatile-util.h"

static int make_volatile(const char *root) {
        _cleanup_free_ char *old_usr = NULL;
        int r;

        assert(root);

        r = chase("/usr", root, CHASE_PREFIX_ROOT, &old_usr, NULL);
        if (r < 0)
                return log_error_errno(r, "/usr not available in old root: %m");

        r = mkdir_p("/run/systemd/volatile-sysroot", 0700);
        if (r < 0)
                return log_error_errno(r, "Couldn't generate volatile sysroot directory: %m");

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", "/run/systemd/volatile-sysroot", "tmpfs", MS_STRICTATIME, "mode=0755" TMPFS_LIMITS_ROOTFS);
        if (r < 0)
                goto finish_rmdir;

        if (mkdir("/run/systemd/volatile-sysroot/usr", 0755) < 0) {
                r = log_error_errno(errno, "Failed to create /usr directory: %m");
                goto finish_umount;
        }

        r = mount_nofollow_verbose(LOG_ERR, old_usr, "/run/systemd/volatile-sysroot/usr", NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                goto finish_umount;

        r = bind_remount_recursive("/run/systemd/volatile-sysroot/usr", MS_RDONLY, MS_RDONLY, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to remount /usr read-only: %m");
                goto finish_umount;
        }

        r = umount_recursive(root, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to unmount %s: %m", root);
                goto finish_umount;
        }

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                log_warning_errno(errno, "Failed to remount %s MS_SLAVE|MS_REC, ignoring: %m", root);

        r = mount_nofollow_verbose(LOG_ERR, "/run/systemd/volatile-sysroot", root, NULL, MS_MOVE, NULL);

finish_umount:
        (void) umount_recursive("/run/systemd/volatile-sysroot", 0);

finish_rmdir:
        (void) rmdir("/run/systemd/volatile-sysroot");

        return r;
}

static int make_overlay(const char *root, int overlay_type) {
        _cleanup_free_ char *escaped_path = NULL, *usr_path = NULL;
        bool tmpfs_mounted = false;
        const char *options = NULL, *overlay_name = NULL;
        _cleanup_free_ char *mount_path = NULL;
        const char *overlay_dir = NULL;
        const char *upper_dir = NULL;
        const char *work_dir = NULL;
        int r;

        assert(root);

        if (overlay_type == VOLATILE_OVERLAY_ROOT) {
                overlay_name = "overlay-root";
                mount_path = strdup(root);
                if (!mount_path)
                        return log_oom();
        } else {
                assert(overlay_type == VOLATILE_OVERLAY_USR);
                overlay_name = "overlay-usr";
                mount_path = strjoin(root, "/usr");
                if (!mount_path)
                        return log_oom();
        }

        overlay_dir = strjoina("/run/systemd/", overlay_name);
        if (!overlay_dir)
                return log_oom();
        upper_dir = strjoina(overlay_dir, "/upper");
        if (!upper_dir)
                return log_oom();
        work_dir = strjoina(overlay_dir, "/work");
        if (!work_dir)
                return log_oom();

        r = mkdir_p(overlay_dir, 0700);
        if (r < 0)
                return log_error_errno(r, "Couldn't create overlay %s directory: %m", overlay_name);

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", overlay_dir, "tmpfs", MS_STRICTATIME, "mode=0755" TMPFS_LIMITS_ROOTFS);
        if (r < 0)
                goto finish;

        tmpfs_mounted = true;

        if (mkdir(upper_dir, 0755) < 0) {
                r = log_error_errno(errno, "Failed to create %s: %m", upper_dir);
                goto finish;
        }

        if (mkdir(work_dir, 0755) < 0) {
                r = log_error_errno(errno, "Failed to create %s: %m", work_dir);
                goto finish;
        }

        if (overlay_type == VOLATILE_OVERLAY_USR) {
                /* Verify that /usr exists in the sysroot before creating overlay */
                r = chase("/usr", root, CHASE_PREFIX_ROOT, &usr_path, NULL);
                if (r < 0)
                        return log_error_errno(r, "/usr not available in sysroot: %m");
        }

        escaped_path = shell_escape(mount_path, ",:");
        if (!escaped_path) {
                r = log_oom();
                goto finish;
        }

        options = strjoina("lowerdir=", escaped_path, ",upperdir=", upper_dir, ",workdir=", work_dir);
        r = mount_nofollow_verbose(LOG_ERR, "overlay", mount_path, "overlay", 0, options);

finish:
        if (tmpfs_mounted)
                (void) umount_verbose(LOG_ERR, overlay_dir, UMOUNT_NOFOLLOW);

        (void) rmdir(overlay_dir);
        return r;
}

static int run(int argc, char *argv[]) {
        VolatileMode m = _VOLATILE_MODE_INVALID;
        const char *root;
        dev_t devt;
        int r;

        log_setup();

        if (argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments. Expected directory and mode.");

        r = query_volatile_mode(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to determine volatile mode from kernel command line: %m");
        if (r == 0 && argc >= 2) {
                /* The kernel command line always wins. However if nothing was set there, the argument passed here wins instead. */
                m = volatile_mode_from_string(argv[1]);
                if (m < 0)
                        return log_error_errno(m, "Couldn't parse volatile mode: %s", argv[1]);
        }

        if (argc < 3)
                root = "/sysroot";
        else {
                root = argv[2];

                if (isempty(root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Directory name cannot be empty.");
                if (!path_is_absolute(root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Directory must be specified as absolute path.");
                if (path_equal(root, "/"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Directory cannot be the root directory.");
        }

        if (!IN_SET(m, VOLATILE_YES, VOLATILE_OVERLAY_ROOT, VOLATILE_OVERLAY_USR))
                return 0;

        r = path_is_mount_point_full(root, /* root= */ NULL, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Couldn't determine whether %s is a mount point: %m", root);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a mount point.", root);

        r = path_is_temporary_fs(root);
        if (r < 0)
                return log_error_errno(r, "Couldn't determine whether %s is a temporary file system: %m", root);
        if (r > 0) {
                log_info("%s already is a temporary file system.", root);
                return 0;
        }

        if (IN_SET(m, VOLATILE_YES, VOLATILE_OVERLAY_ROOT, VOLATILE_OVERLAY_USR)) {
                /* We are about to replace the root directory with something else. Later code might want to know what we
                * replaced here, hence let's save that information as a symlink we can later use. (This is particularly
                * relevant for the overlayfs case where we'll fully obstruct the view onto the underlying device, hence
                * querying the backing device node from the file system directly is no longer possible. */
                r = get_block_device_harder(root, &devt);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine device major/minor of %s: %m", root);
                else if (r > 0) { /* backed by block device */
                        _cleanup_free_ char *dn = NULL;

                        r = device_path_make_major_minor(S_IFBLK, devt, &dn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format device node path: %m");

                        if (symlink(dn, "/run/systemd/volatile-root") < 0)
                                log_warning_errno(errno, "Failed to create symlink /run/systemd/volatile-root: %m");
                }
        }

        switch (m) {
        case VOLATILE_YES:
                return make_volatile(root);
        case VOLATILE_OVERLAY_ROOT:
                return make_overlay(root, VOLATILE_OVERLAY_ROOT);
        case VOLATILE_OVERLAY_USR:
                return make_overlay(root, VOLATILE_OVERLAY_USR);
        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid volatile mode: %d", m);
        }
}

DEFINE_MAIN_FUNCTION(run);
