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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mntent.h>

#include "log.h"
#include "util.h"
#include "path-util.h"
#include "set.h"
#include "mount-setup.h"
#include "exit-status.h"

/* Goes through /etc/fstab and remounts all API file systems, applying
 * options that are in /etc/fstab that systemd might not have
 * respected */

int main(int argc, char *argv[]) {
        int ret = EXIT_FAILURE;
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent* me;
        Hashmap *pids = NULL;

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
                if (errno == ENOENT)
                        return EXIT_SUCCESS;

                log_error("Failed to open /etc/fstab: %m");
                return EXIT_FAILURE;
        }

        pids = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!pids) {
                log_error("Failed to allocate set");
                goto finish;
        }

        ret = EXIT_SUCCESS;

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
                        log_error("Failed to fork: %m");
                        ret = EXIT_FAILURE;
                        continue;
                }

                if (pid == 0) {
                        const char *arguments[5];
                        /* Child */

                        arguments[0] = "/bin/mount";
                        arguments[1] = me->mnt_dir;
                        arguments[2] = "-o";
                        arguments[3] = "remount";
                        arguments[4] = NULL;

                        execv("/bin/mount", (char **) arguments);

                        log_error("Failed to execute /bin/mount: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Parent */

                s = strdup(me->mnt_dir);
                if (!s) {
                        log_oom();
                        ret = EXIT_FAILURE;
                        continue;
                }


                k = hashmap_put(pids, UINT_TO_PTR(pid), s);
                if (k < 0) {
                        log_error("Failed to add PID to set: %s", strerror(-k));
                        ret = EXIT_FAILURE;
                        continue;
                }
        }

        while (!hashmap_isempty(pids)) {
                siginfo_t si = {};
                char *s;

                if (waitid(P_ALL, 0, &si, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("waitid() failed: %m");
                        ret = EXIT_FAILURE;
                        break;
                }

                s = hashmap_remove(pids, UINT_TO_PTR(si.si_pid));
                if (s) {
                        if (!is_clean_exit(si.si_code, si.si_status, NULL)) {
                                if (si.si_code == CLD_EXITED)
                                        log_error("/bin/mount for %s exited with exit status %i.", s, si.si_status);
                                else
                                        log_error("/bin/mount for %s terminated by signal %s.", s, signal_to_string(si.si_status));

                                ret = EXIT_FAILURE;
                        }

                        free(s);
                }
        }

finish:

        if (pids)
                hashmap_free_free(pids);

        return ret;
}
