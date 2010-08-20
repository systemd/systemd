/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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
#include "set.h"
#include "mount-setup.h"

/* Goes through /etc/fstab and remounts all API file systems, applying
 * options that are in /etc/fstab that systemd might not have
 * respected */

int main(int argc, char *argv[]) {
        int ret = 1;
        FILE *f = NULL;
        struct mntent* me;
        Hashmap *pids = NULL;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return 1;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (!(f = setmntent("/etc/fstab", "r"))) {
                log_error("Failed to open /etc/fstab: %m");
                goto finish;
        }

        if (!(pids = hashmap_new(trivial_hash_func, trivial_compare_func))) {
                log_error("Failed to allocate set");
                goto finish;
        }

        ret = 0;

        while ((me = getmntent(f))) {
                pid_t pid;
                int k;
                char *s;

                if (!mount_point_is_api(me->mnt_dir))
                        continue;

                log_debug("Remounting %s", me->mnt_dir);

                if ((pid = fork()) < 0) {
                        log_error("Failed to fork: %m");
                        ret = 1;
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
                        _exit(1);
                }

                /* Parent */

                s = strdup(me->mnt_dir);

                if ((k = hashmap_put(pids, UINT_TO_PTR(pid), s)) < 0) {
                        log_error("Failed to add PID to set: %s", strerror(-k));
                        ret = 1;
                        continue;
                }
        }

        while (!hashmap_isempty(pids)) {
                siginfo_t si;
                char *s;

                zero(si);
                if (waitid(P_ALL, 0, &si, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("waitid() failed: %m");
                        ret = 1;
                        break;
                }

                if ((s = hashmap_remove(pids, UINT_TO_PTR(si.si_pid)))) {
                        if (!is_clean_exit(si.si_code, si.si_status)) {
                                if (si.si_code == CLD_EXITED)
                                        log_error("/bin/mount for %s exited with exit status %i.", s, si.si_status);
                                else
                                        log_error("/bin/mount for %s terminated by signal %s.", s, signal_to_string(si.si_status));

                                ret = 1;
                        }

                        free(s);
                }
        }

finish:

        if (pids)
                hashmap_free_free(pids);

        if (f)
                endmntent(f);

        return ret;
}
