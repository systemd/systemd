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
#include <unistd.h>

#include "util.h"
#include "def.h"
#include "killall.h"
#include "set.h"

#define TIMEOUT_USEC (10 * USEC_PER_SEC)

static bool ignore_proc(pid_t pid) {
        _cleanup_fclose_ FILE *f = NULL;
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

        f = fopen(procfs_file_alloca(pid, "cmdline"), "re");
        if (!f)
                return true; /* not really, but has the desired effect */

        count = fread(&c, 1, 1, f);

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

static void wait_for_children(Set *pids, sigset_t *mask) {
        usec_t until;

        assert(mask);

        if (set_isempty(pids))
                return;

        until = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;
        for (;;) {
                struct timespec ts;
                int k;
                usec_t n;
                void *p;
                Iterator i;

                /* First, let the kernel inform us about killed
                 * children. Most processes will probably be our
                 * children, but some are not (might be our
                 * grandchildren instead...). */
                for (;;) {
                        pid_t pid;

                        pid = waitpid(-1, NULL, WNOHANG);
                        if (pid == 0)
                                break;
                        if (pid < 0) {
                                if (errno == ECHILD)
                                        break;

                                log_error("waitpid() failed: %m");
                                return;
                        }

                        set_remove(pids, ULONG_TO_PTR(pid));
                }

                /* Now explicitly check who might be remaining, who
                 * might not be our child. */
                SET_FOREACH(p, pids, i) {

                        /* We misuse getpgid as a check whether a
                         * process still exists. */
                        if (getpgid((pid_t) PTR_TO_ULONG(p)) >= 0)
                                continue;

                        if (errno != ESRCH)
                                continue;

                        set_remove(pids, p);
                }

                if (set_isempty(pids))
                        return;

                n = now(CLOCK_MONOTONIC);
                if (n >= until)
                        return;

                timespec_store(&ts, until - n);
                k = sigtimedwait(mask, NULL, &ts);
                if (k != SIGCHLD) {

                        if (k < 0 && errno != EAGAIN) {
                                log_error("sigtimedwait() failed: %m");
                                return;
                        }

                        if (k >= 0)
                                log_warning("sigtimedwait() returned unexpected signal.");
                }
        }
}

static int killall(int sig, Set *pids) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *d;

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

                if (sig == SIGKILL) {
                        _cleanup_free_ char *s;

                        get_process_comm(pid, &s);
                        log_notice("Sending SIGKILL to PID %lu (%s).", (unsigned long) pid, strna(s));
                }

                if (kill(pid, sig) >= 0) {
                        if (pids)
                                set_put(pids, ULONG_TO_PTR((unsigned long) pid));
                } else if (errno != ENOENT)
                        log_warning("Could not kill %d: %m", pid);
        }

        return set_size(pids);
}

void broadcast_signal(int sig, bool wait_for_exit) {
        sigset_t mask, oldmask;
        Set *pids = NULL;

        if (wait_for_exit)
                pids = set_new(trivial_hash_func, trivial_compare_func);

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        if (kill(-1, SIGSTOP) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGSTOP) failed: %m");

        killall(sig, pids);

        if (kill(-1, SIGCONT) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGCONT) failed: %m");

        if (wait_for_exit)
                wait_for_children(pids, &mask);

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);

        set_free(pids);
}
