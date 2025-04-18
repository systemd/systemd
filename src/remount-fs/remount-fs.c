/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <mntent.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "env-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fstab-util.h"
#include "log.h"
#include "main-func.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "strv.h"

/* Goes through /etc/fstab and remounts all API file systems, applying options that are in /etc/fstab that
 * systemd might not have respected. */

static int track_pid(Hashmap **h, const char *path, pid_t pid) {
        _cleanup_free_ char *c = NULL;
        int r;

        assert(h);
        assert(path);
        assert(pid_is_valid(pid));

        c = strdup(path);
        if (!c)
                return log_oom();

        r = hashmap_ensure_put(h, &trivial_hash_ops_value_free, PID_TO_PTR(pid), c);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store pid " PID_FMT, pid);

        TAKE_PTR(c);
        return 0;
}

static int do_remount(const char *path, bool force_rw, Hashmap **pids) {
        pid_t pid;
        int r;

        log_debug("Remounting %s...", path);

        r = safe_fork(force_rw ? "(remount-rw)" : "(remount)",
                      FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execv(MOUNT_PATH,
                      STRV_MAKE(MOUNT_PATH,
                                path,
                                "-o",
                                force_rw ? "remount,rw" : "remount"));
                log_error_errno(errno, "Failed to execute " MOUNT_PATH ": %m");
                _exit(EXIT_FAILURE);
        }

        /* Parent */
        return track_pid(pids, path, pid);
}

static int device_node_uuid(const char *path, sd_id128_t *ret_uuid) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        r = sd_device_new_from_devname(&device, path);
        if (r < 0)
                return log_warning_errno(r, "Failed to create device from %s: %m", path);

        const char *uuid;
        r = sd_device_get_property_value(device, "ID_FS_UUID", &uuid);
        if (r < 0)
                return log_warning_errno(r, "Failed to get filesystem UUID for device %s: %m", path);

        r = sd_id128_from_string(uuid, ret_uuid);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse ID_FS_UUID '%s' for device %s: %m",
                                         uuid, path);
        return 0;
}

static void mount_point_check(const struct mntent *me) {
        _cleanup_free_ char *what = NULL, *where = NULL, *type = NULL;
        int r;

        r = path_get_mount_info(ASSERT_PTR(me)->mnt_dir, &what, &where, &type, /* options= */ NULL);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to acquire information about mount point %s: %m", me->mnt_dir);
        if (!path_equal(me->mnt_dir, where))  /* We got the containing mount point */
                return log_debug("Mount point \"%s\" is not mounted.", me->mnt_dir);

        if (!streq(type, me->mnt_type) && !streq(me->mnt_type, "auto"))
                return log_info("Note: file system type mounted at \"%s\" doesn't match fstab (type %s vs. %s).\n"
                                "Consider adjusting fstab.",
                                me->mnt_dir, type, me->mnt_type);

        if (!fstype_is_blockdev_backed(type))
                return log_debug("File system type mounted at \"%s\" matches fstab.", me->mnt_dir);

        /* Figure out if the two paths point at the same device node */
        _cleanup_free_ char *node = fstab_node_to_udev_node(me->mnt_fsname);
        if (!node)
                return (void) log_oom();

        _cleanup_close_ int pin_a = -EBADF, pin_b = -EBADF;

        pin_a = r = RET_NERRNO(open(what, O_PATH|O_CLOEXEC));
        if (r < 0)
                return (void) log_debug_errno(r, "Cannot open mount device %s: %m, ignoring.", what);
        pin_b = r = RET_NERRNO(open(node, O_PATH|O_CLOEXEC));
        if (r == -ENOENT)
                return (void) log_notice_errno(r, "Mount device %s specified in fstab doesn't exist,\n"
                                                  "             %s is mounted instead.\n"
                                                  "Consider adjusting fstab.",
                                               node, what);
        if (r < 0)
                return (void) log_warning_errno(r, "Cannot open mount device %s specified in fstab, ignoring: %m\n",
                                                node);

        struct stat sta, stb;
        if (fstat(pin_a, &sta) < 0)
                return (void) log_warning_errno(errno, "Cannot stat %s: %m", what);
        if (fstat(pin_b, &stb) < 0)
                return (void) log_warning_errno(errno, "Cannot stat %s: %m", node);
        r = sta.st_dev != stb.st_dev;

        if (r == 0) {
                /* Try to figure out if the file system identifier matches…
                 * This way we cover multi-device file systems like btrfs or bcachefs. */
                sd_id128_t uuid_a, uuid_b;

                if (device_node_uuid(what, &uuid_a) < 0 ||
                    device_node_uuid(node, &uuid_b) < 0)
                        return;

                r = sd_id128_equal(uuid_a, uuid_b);
        }

        if (r > 0)
                log_debug("File system mounted at \"%s\" matches fstab.", me->mnt_dir);
        else
                log_info("Note: file system mounted at \"%s\" doesn't match fstab (%s vs. %s)\n"
                         "Consider adjusting fstab.",
                         me->mnt_dir, what, me->mnt_fsname);
}

static int remount_by_fstab(Hashmap **ret_pids) {
        _cleanup_hashmap_free_ Hashmap *pids = NULL;
        _cleanup_endmntent_ FILE *f = NULL;
        bool has_root = false;
        struct mntent *me;
        int r;

        assert(ret_pids);

        if (!fstab_enabled())
                return 0;

        f = setmntent(fstab_path(), "re");
        if (!f) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", fstab_path());

                return 0;
        }

        while ((me = getmntent(f))) {
                /* Remount the root fs, /usr, and all API VFSs */
                if (!mount_point_is_api(me->mnt_dir) &&
                    !PATH_IN_SET(me->mnt_dir, "/", "/usr"))
                        continue;

                if (path_equal(me->mnt_dir, "/"))
                        has_root = true;

                mount_point_check(me);

                r = do_remount(me->mnt_dir, /* force_rw= */ false, &pids);
                if (r < 0)
                        return r;
        }

        *ret_pids = TAKE_PTR(pids);
        return has_root;
}

static int run(int argc, char *argv[]) {
        _cleanup_hashmap_free_ Hashmap *pids = NULL;
        int r;

        log_setup();

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        umask(0022);

        r = remount_by_fstab(&pids);
        if (r < 0)
                return r;
        if (r == 0) {
                /* The $SYSTEMD_REMOUNT_ROOT_RW environment variable is set by systemd-gpt-auto-generator to tell us
                 * whether to remount things. We honour it only if there's no explicit line in /etc/fstab configured
                 * which takes precedence. */

                r = getenv_bool("SYSTEMD_REMOUNT_ROOT_RW");
                if (r < 0 && r != -ENXIO)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REMOUNT_ROOT_RW, ignoring: %m");

                if (r > 0) {
                        r = do_remount("/", /* force_rw= */ true, &pids);
                        if (r < 0)
                                return r;
                }
        }

        r = 0;
        while (!hashmap_isempty(pids)) {
                _cleanup_free_ char *s = NULL;
                siginfo_t si = {};

                if (waitid(P_ALL, 0, &si, WEXITED) < 0) {
                        if (errno == EINTR)
                                continue;

                        return log_error_errno(errno, "waitid() failed: %m");
                }

                s = hashmap_remove(pids, PID_TO_PTR(si.si_pid));
                if (s &&
                    !is_clean_exit(si.si_code, si.si_status, EXIT_CLEAN_COMMAND, NULL)) {
                        if (si.si_code == CLD_EXITED)
                                log_error(MOUNT_PATH " for %s exited with exit status %i.", s, si.si_status);
                        else
                                log_error(MOUNT_PATH " for %s terminated by signal %s.", s, signal_to_string(si.si_status));

                        r = -ENOEXEC;
                }
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
