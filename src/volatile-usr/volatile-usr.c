/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/stat.h>
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
#include "string-util.h"
#include "volatile-util.h"

static int make_overlay_usr(const char *sysroot_path) {
        _cleanup_free_ char *escaped_usr_path = NULL, *usr_path = NULL;
        bool tmpfs_mounted = false;
        const char *options = NULL;
        int r;

        assert(sysroot_path);

        /* Create the overlay directory structure */
        r = mkdir_p("/run/systemd/overlay-usr", 0700);
        if (r < 0)
                return log_error_errno(r, "Couldn't create overlay usr directory: %m");

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", "/run/systemd/overlay-usr", "tmpfs", MS_STRICTATIME, "mode=0755" TMPFS_LIMITS_ROOTFS);
        if (r < 0)
                goto finish;

        tmpfs_mounted = true;

        if (mkdir("/run/systemd/overlay-usr/upper", 0755) < 0) {
                r = log_error_errno(errno, "Failed to create /run/systemd/overlay-usr/upper: %m");
                goto finish;
        }

        if (mkdir("/run/systemd/overlay-usr/work", 0755) < 0) {
                r = log_error_errno(errno, "Failed to create /run/systemd/overlay-usr/work: %m");
                goto finish;
        }

        /* Create the usr directory in the sysroot if it doesn't exist */
        r = chase("/usr", sysroot_path, CHASE_PREFIX_ROOT, &usr_path, NULL);
        if (r < 0)
                return log_error_errno(r, "/usr not available in sysroot: %m");

        escaped_usr_path = shell_escape(usr_path, ",:");
        if (!escaped_usr_path) {
                r = log_oom();
                goto finish;
        }

        options = strjoina("lowerdir=", escaped_usr_path, ",upperdir=/run/systemd/overlay-usr/upper,workdir=/run/systemd/overlay-usr/work");
        r = mount_nofollow_verbose(LOG_ERR, "overlay", usr_path, "overlay", 0, options);

finish:
        if (tmpfs_mounted)
                (void) umount_verbose(LOG_ERR, "/run/systemd/overlay-usr", UMOUNT_NOFOLLOW);

        (void) rmdir("/run/systemd/overlay-usr");
        return r;
}

static int run(int argc, char *argv[]) {
        VolatileMode m = _VOLATILE_MODE_INVALID;
        const char *sysroot_path;
        dev_t devt;
        int r;

        log_setup();

        if (argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments. Expected sysroot directory and mode.");

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
                sysroot_path = "/sysroot";
        else {
                sysroot_path = argv[2];

                if (isempty(sysroot_path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Sysroot directory name cannot be empty.");
                if (!path_is_absolute(sysroot_path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Sysroot directory must be specified as absolute path.");
        }

        if (m != VOLATILE_OVERLAY_USR)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid volatile mode: %s", argv[1]);

        /* Check if sysroot is a mount point */
        r = path_is_mount_point_full(sysroot_path, /* root = */ NULL, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Couldn't determine whether %s is a mount point: %m", sysroot_path);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a mount point.", sysroot_path);

        /* We are about to overlay the /usr directory. Let's save information about the backing device
         * for later reference, similar to what systemd-volatile-root does. */
        r = get_block_device_harder(sysroot_path, &devt);
        if (r < 0)
                return log_error_errno(r, "Failed to determine device major/minor of %s: %m", sysroot_path);
        else if (r > 0) { /* backed by block device */
                _cleanup_free_ char *dn = NULL;

                r = device_path_make_major_minor(S_IFBLK, devt, &dn);
                if (r < 0)
                        return log_error_errno(r, "Failed to format device node path: %m");

                if (symlink(dn, "/run/systemd/volatile-usr") < 0)
                        log_warning_errno(errno, "Failed to create symlink /run/systemd/volatile-usr: %m");
        }

        return make_overlay_usr(sysroot_path);
}

DEFINE_MAIN_FUNCTION(run);
