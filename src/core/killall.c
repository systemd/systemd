/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

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

#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "util.h"
#include "def.h"
#include "killall.h"

#define TIMEOUT_USEC (5 * USEC_PER_SEC)

static bool ignore_proc(pid_t pid) {
        char buf[PATH_MAX];
        FILE *f;
        char c;
        size_t count;
        uid_t uid;
        int r;

        /* We are PID 1, let's not commit suicide */
        if (pid == 1)
                return true;

        r = get_process_uid(pid, &uid);
        if (r < 0)
                return true; /* not really, but better safe than sorry */

        /* Non-root processes otherwise are always subject to be killed */
        if (uid != 0)
                return false;

        snprintf(buf, sizeof(buf), "/proc/%lu/cmdline", (unsigned long) pid);
        char_array_0(buf);

        f = fopen(buf, "re");
        if (!f)
                return true; /* not really, but has the desired effect */

        count = fread(&c, 1, 1, f);
        fclose(f);

        /* Kernel threads have an empty cmdline */
        if (count <= 0)
                return true;

        /* Processes with argv[0][0] = '@' we ignore from the killing
         * spree.
         *
         * http://www.freedesktop.org/wiki/Software/systemd/RootStorageDaemons */
        if (count == 1 && c == '@')
                return true;

        return false;
}

static void wait_for_children(int n_processes, sigset_t *mask) {
        usec_t until;

        assert(mask);

        until = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;
        for (;;) {
                struct timespec ts;
                int k;
                usec_t n;

                for (;;) {
                        pid_t pid = waitpid(-1, NULL, WNOHANG);

                        if (pid == 0)
                                break;

                        if (pid < 0 && errno == ECHILD)
                                return;

                        if (n_processes > 0)
                                if (--n_processes == 0)
                                        return;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= until)
                        return;

                timespec_store(&ts, until - n);

                if ((k = sigtimedwait(mask, NULL, &ts)) != SIGCHLD) {

                        if (k < 0 && errno != EAGAIN) {
                                log_error("sigtimedwait() failed: %m");
                                return;
                        }

                        if (k >= 0)
                                log_warning("sigtimedwait() returned unexpected signal.");
                }
        }
}

static int killall(int sig) {
        DIR *dir;
        struct dirent *d;
        unsigned int n_processes = 0;

        dir = opendir("/proc");
        if (!dir)
                return -errno;

        while ((d = readdir(dir))) {
                pid_t pid;

                if (d->d_type != DT_DIR &&
                    d->d_type != DT_UNKNOWN)
                        continue;

                if (parse_pid(d->d_name, &pid) < 0)
                        continue;

                if (ignore_proc(pid))
                        continue;

                if (kill(pid, sig) >= 0)
                        n_processes++;
                else if (errno != ENOENT)
                        log_warning("Could not kill %d: %m", pid);
        }

        closedir(dir);

        return n_processes;
}

void broadcast_signal(int sig, bool wait) {
        sigset_t mask, oldmask;
        int n_processes;

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        if (kill(-1, SIGSTOP) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGSTOP) failed: %m");

        n_processes = killall(sig);

        if (kill(-1, SIGCONT) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGCONT) failed: %m");

        if (n_processes <= 0)
                goto finish;

        if (wait)
                wait_for_children(n_processes, &mask);

finish:
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
}
