/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <mntent.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "exit-status.h"
#include "log.h"
#include "main-func.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "strv.h"
#include "util.h"

/* Goes through /etc/fstab and remounts all API file systems, applying
 * options that are in /etc/fstab that systemd might not have
 * respected */

static int run(int argc, char *argv[]) {
        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent* me;
        int r;

        log_setup_service();

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        umask(0022);

        f = setmntent("/etc/fstab", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open /etc/fstab: %m");
        }

        pids = hashmap_new(NULL);
        if (!pids)
                return log_oom();

        while ((me = getmntent(f))) {
                _cleanup_free_ char *s = NULL;
                pid_t pid;
                int k;

                /* Remount the root fs, /usr and all API VFS */
                if (!mount_point_is_api(me->mnt_dir) &&
                    !path_equal(me->mnt_dir, "/") &&
                    !path_equal(me->mnt_dir, "/usr"))
                        continue;

                log_debug("Remounting %s", me->mnt_dir);

                r = safe_fork("(remount)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */

                        execv(MOUNT_PATH, STRV_MAKE(MOUNT_PATH, me->mnt_dir, "-o", "remount"));

                        log_error_errno(errno, "Failed to execute " MOUNT_PATH ": %m");
                        _exit(EXIT_FAILURE);
                }

                /* Parent */

                s = strdup(me->mnt_dir);
                if (!s)
                        return log_oom();

                k = hashmap_put(pids, PID_TO_PTR(pid), s);
                if (k < 0)
                        return log_oom();
                TAKE_PTR(s);
        }

        r = 0;
        while (!hashmap_isempty(pids)) {
                siginfo_t si = {};
                _cleanup_free_ char *s = NULL;

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
