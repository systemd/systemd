/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "exit-status.h"
#include "format-util.h"
#include "fstab-util.h"
#include "hashmap.h"
#include "libmount-util.h"
#include "log.h"
#include "main-func.h"
#include "mount-setup.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"

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
        if (r < 0)
                return log_error_errno(r, "Failed to store pid " PID_FMT " for mount '%s': %m", pid, path);

        TAKE_PTR(c);
        return 0;
}

static int do_remount(const char *path, bool force_rw, Hashmap **pids) {
        int r;

        assert(path);

        log_debug("Remounting %s...", path);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        force_rw ? "(remount-rw)" : "(remount)",
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG,
                        &pidref);
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
        return track_pid(pids, path, pidref.pid);
}

static int remount_by_fstab(Hashmap **ret_pids) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        _cleanup_hashmap_free_ Hashmap *pids = NULL;
        bool has_root = false;
        int r;

        assert(ret_pids);

        if (!fstab_enabled())
                return 0;

        r = libmount_parse_fstab(&table, &iter);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse fstab: %m");

        for (;;) {
                struct libmnt_fs *fs;

                r = sym_mnt_table_next_fs(table, iter, &fs);
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from fstab: %m");
                if (r > 0) /* EOF */
                        break;

                const char *target = sym_mnt_fs_get_target(fs);
                if (!target)
                        continue;

                /* Remount the root fs, /usr/, and all API VFSs */

                if (path_equal(target, "/"))
                        has_root = true;
                else if (!path_equal(target, "/usr") && !mount_point_is_api(target))
                        continue;

                r = do_remount(target, /* force_rw= */ false, &pids);
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
