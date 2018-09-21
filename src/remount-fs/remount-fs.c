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

int main(int argc, char *argv[]) {
        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent* me;
        int r;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        f = setmntent("/etc/fstab", "re");
        if (!f) {
                if (errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                r = log_error_errno(errno, "Failed to open /etc/fstab: %m");
                goto finish;
        }

        pids = hashmap_new(NULL);
        if (!pids) {
                r = log_oom();
                goto finish;
        }

        while ((me = getmntent(f))) {
                pid_t pid;
                int k;
                char *s;

                /* Remount the root fs, /usr and all API VFS */
                if (!mount_point_is_api(me->mnt_dir) &&
                    !path_equal(me->mnt_dir, "/") &&
                    !path_equal(me->mnt_dir, "/usr"))
                        continue;

                log_debug("Remounting %s", me->mnt_dir);

                r = safe_fork("(remount)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        /* Child */

                        execv(MOUNT_PATH, STRV_MAKE(MOUNT_PATH, me->mnt_dir, "-o", "remount"));

                        log_error_errno(errno, "Failed to execute " MOUNT_PATH ": %m");
                        _exit(EXIT_FAILURE);
                }

                /* Parent */

                s = strdup(me->mnt_dir);
                if (!s) {
                        r = log_oom();
                        goto finish;
                }

                k = hashmap_put(pids, PID_TO_PTR(pid), s);
                if (k < 0) {
                        free(s);
                        r = log_oom();
                        goto finish;
                }
        }

        r = 0;
        while (!hashmap_isempty(pids)) {
                siginfo_t si = {};
                char *s;

                if (waitid(P_ALL, 0, &si, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        r = log_error_errno(errno, "waitid() failed: %m");
                        goto finish;
                }

                s = hashmap_remove(pids, PID_TO_PTR(si.si_pid));
                if (s) {
                        if (!is_clean_exit(si.si_code, si.si_status, EXIT_CLEAN_COMMAND, NULL)) {
                                if (si.si_code == CLD_EXITED)
                                        log_error(MOUNT_PATH " for %s exited with exit status %i.", s, si.si_status);
                                else
                                        log_error(MOUNT_PATH " for %s terminated by signal %s.", s, signal_to_string(si.si_status));

                                r = -ENOEXEC;
                        }

                        free(s);
                }
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
