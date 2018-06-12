/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/mount.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "stat-util.h"
#include "volatile-util.h"
#include "string-util.h"
#include "path-util.h"

static int make_volatile(const char *path) {
        _cleanup_free_ char *old_usr = NULL;
        int r;

        r = path_is_mount_point(path, NULL, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Couldn't determine whether %s is a mount point: %m", path);
        if (r == 0) {
                log_error("%s is not a mount point.", path);
                return -EINVAL;
        }

        r = path_is_temporary_fs(path);
        if (r < 0)
                return log_error_errno(r, "Couldn't determine whether %s is a temporary file system: %m", path);
        if (r > 0) {
                log_info("%s already is a temporary file system.", path);
                return 0;
        }

        r = chase_symlinks("/usr", path, CHASE_PREFIX_ROOT, &old_usr);
        if (r < 0)
                return log_error_errno(r, "/usr not available in old root: %m");

        r = mkdir_p("/run/systemd/volatile-sysroot", 0700);
        if (r < 0)
                return log_error_errno(r, "Couldn't generate volatile sysroot directory: %m");

        r = mount_verbose(LOG_ERR, "tmpfs", "/run/systemd/volatile-sysroot", "tmpfs", MS_STRICTATIME, "mode=755");
        if (r < 0)
                goto finish_rmdir;

        if (mkdir("/run/systemd/volatile-sysroot/usr", 0755) < 0) {
                r = -errno;
                goto finish_umount;
        }

        r = mount_verbose(LOG_ERR, old_usr, "/run/systemd/volatile-sysroot/usr", NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                goto finish_umount;

        r = bind_remount_recursive("/run/systemd/volatile-sysroot/usr", true, NULL);
        if (r < 0)
                goto finish_umount;

        r = umount_recursive(path, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to unmount %s: %m", path);
                goto finish_umount;
        }

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                log_warning_errno(errno, "Failed to remount %s MS_SLAVE|MS_REC: %m", path);

        r = mount_verbose(LOG_ERR, "/run/systemd/volatile-sysroot", path, NULL, MS_MOVE, NULL);

finish_umount:
        (void) umount_recursive("/run/systemd/volatile-sysroot", 0);

finish_rmdir:
        (void) rmdir("/run/systemd/volatile-sysroot");

        return r;
}

int main(int argc, char *argv[]) {
        VolatileMode m = _VOLATILE_MODE_INVALID;
        const char *path;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc > 3) {
                log_error("Too many arguments. Expected directory and mode.");
                r = -EINVAL;
                goto finish;
        }

        r = query_volatile_mode(&m);
        if (r < 0) {
                log_error_errno(r, "Failed to determine volatile mode from kernel command line.");
                goto finish;
        }
        if (r == 0 && argc >= 2) {
                /* The kernel command line always wins. However if nothing was set there, the argument passed here wins instead. */
                m = volatile_mode_from_string(argv[1]);
                if (m < 0) {
                        log_error("Couldn't parse volatile mode: %s", argv[1]);
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (argc < 3)
                path = "/sysroot";
        else {
                path = argv[2];

                if (isempty(path)) {
                        log_error("Directory name cannot be empty.");
                        r = -EINVAL;
                        goto finish;
                }
                if (!path_is_absolute(path)) {
                        log_error("Directory must be specified as absolute path.");
                        r = -EINVAL;
                        goto finish;
                }
                if (path_equal(path, "/")) {
                        log_error("Directory cannot be the root directory.");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (m != VOLATILE_YES) {
                r = 0;
                goto finish;
        }

        r = make_volatile(path);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
