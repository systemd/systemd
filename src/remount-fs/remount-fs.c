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

/* Goes through /etc/fstab and remounts all API file systems, applying options that are in /etc/fstab that systemd
 * might not have respected */

static int track_pid(Hashmap **h, const char *path, pid_t pid) {
        _cleanup_free_ char *c = NULL;
        int r;

        assert(h);
        assert(path);
        assert(pid_is_valid(pid));

        r = hashmap_ensure_allocated(h, NULL);
        if (r < 0)
                return log_oom();

        c = strdup(path);
        if (!c)
                return log_oom();

        r = hashmap_put(*h, PID_TO_PTR(pid), c);
        if (r < 0)
                return log_oom();

        TAKE_PTR(c);
        return 0;
}

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

        while ((me = getmntent(f))) {
                pid_t pid;

                /* Remount the root fs, /usr and all API VFS */
                if (!mount_point_is_api(me->mnt_dir) &&
                    !PATH_IN_SET(me->mnt_dir, "/", "/usr"))
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
                r = track_pid(&pids, me->mnt_dir, pid);
                if (r < 0)
                        return r;
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
