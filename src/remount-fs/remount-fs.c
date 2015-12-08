/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

        f = setmntent("/etc/fstab", "r");
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

                pid = fork();
                if (pid < 0) {
                        r = log_error_errno(errno, "Failed to fork: %m");
                        goto finish;
                }

                if (pid == 0) {
                        /* Child */

                        (void) reset_all_signal_handlers();
                        (void) reset_signal_mask();
                        (void) prctl(PR_SET_PDEATHSIG, SIGTERM);

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
                        if (!is_clean_exit(si.si_code, si.si_status, NULL)) {
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
