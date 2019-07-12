/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "killall.h"
#include "parse-util.h"
#include "process-util.h"
#include "set.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"

static bool ignore_proc(pid_t pid, bool warn_rootfs) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        char c = 0;
        uid_t uid;
        int r;

        /* We are PID 1, let's not commit suicide */
        if (pid <= 1)
                return true;

        /* Ignore kernel threads */
        r = is_kernel_thread(pid);
        if (r != 0)
                return true; /* also ignore processes where we can't determine this */

        r = get_process_uid(pid, &uid);
        if (r < 0)
                return true; /* not really, but better safe than sorry */

        /* Non-root processes otherwise are always subject to be killed */
        if (uid != 0)
                return false;

        p = procfs_file_alloca(pid, "cmdline");
        f = fopen(p, "re");
        if (!f)
                return true; /* not really, but has the desired effect */

        /* Try to read the first character of the command line. If the cmdline is empty (which might be the case for
         * kernel threads but potentially also other stuff), this line won't do anything, but we don't care much, as
         * actual kernel threads are already filtered out above. */
        (void) fread(&c, 1, 1, f);

        /* Processes with argv[0][0] = '@' we ignore from the killing spree.
         *
         * http://www.freedesktop.org/wiki/Software/systemd/RootStorageDaemons */
        if (c != '@')
                return false;

        if (warn_rootfs &&
            pid_from_same_root_fs(pid) == 0) {

                _cleanup_free_ char *comm = NULL;

                (void) get_process_comm(pid, &comm);

                log_notice("Process " PID_FMT " (%s) has been marked to be excluded from killing. It is "
                           "running from the root file system, and thus likely to block re-mounting of the "
                           "root file system to read-only. Please consider moving it into an initrd file "
                           "system instead.", pid, strna(comm));
        }

        return true;
}

static void log_children_no_yet_killed(Set *pids) {
        _cleanup_free_ char *lst_child = NULL;
        Iterator i;
        void *p;

        SET_FOREACH(p, pids, i) {
                _cleanup_free_ char *s = NULL;

                if (get_process_comm(PTR_TO_PID(p), &s) < 0)
                        (void) asprintf(&s, PID_FMT, PTR_TO_PID(p));

                if (!strextend(&lst_child, ", ", s, NULL)) {
                        log_oom();
                        return;
                }
        }

        if (isempty(lst_child))
                return;

        log_warning("Waiting for process: %s", lst_child + 2);
}

static int wait_for_children(Set *pids, sigset_t *mask, usec_t timeout) {
        usec_t until, date_log_child, n;

        assert(mask);

        /* Return the number of children remaining in the pids set: That correspond to the number
         * of processes still "alive" after the timeout */

        if (set_isempty(pids))
                return 0;

        n = now(CLOCK_MONOTONIC);
        until = usec_add(n, timeout);
        date_log_child = usec_add(n, 10u * USEC_PER_SEC);
        if (date_log_child > until)
                date_log_child = usec_add(n, timeout / 2u);

        for (;;) {
                struct timespec ts;
                int k;
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

                                return log_error_errno(errno, "waitpid() failed: %m");
                        }

                        (void) set_remove(pids, PID_TO_PTR(pid));
                }

                /* Now explicitly check who might be remaining, who
                 * might not be our child. */
                SET_FOREACH(p, pids, i) {

                        /* kill(pid, 0) sends no signal, but it tells
                         * us whether the process still exists. */
                        if (kill(PTR_TO_PID(p), 0) == 0)
                                continue;

                        if (errno != ESRCH)
                                continue;

                        set_remove(pids, p);
                }

                if (set_isempty(pids))
                        return 0;

                n = now(CLOCK_MONOTONIC);
                if (date_log_child > 0 && n >= date_log_child) {
                        log_children_no_yet_killed(pids);
                        /* Log the children not yet killed only once */
                        date_log_child = 0;
                }

                if (n >= until)
                        return set_size(pids);

                if (date_log_child > 0)
                        timespec_store(&ts, MIN(until - n, date_log_child - n));
                else
                        timespec_store(&ts, until - n);

                k = sigtimedwait(mask, NULL, &ts);
                if (k != SIGCHLD) {

                        if (k < 0 && errno != EAGAIN)
                                return log_error_errno(errno, "sigtimedwait() failed: %m");

                        if (k >= 0)
                                log_warning("sigtimedwait() returned unexpected signal.");
                }
        }
}

static int killall(int sig, Set *pids, bool send_sighup) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *d;
        int n_killed = 0;

        /* Send the specified signal to all remaining processes, if not excluded by ignore_proc().
         * Returns the number of processes to which the specified signal was sent */

        dir = opendir("/proc");
        if (!dir)
                return log_warning_errno(errno, "opendir(/proc) failed: %m");

        FOREACH_DIRENT_ALL(d, dir, break) {
                pid_t pid;
                int r;

                if (!IN_SET(d->d_type, DT_DIR, DT_UNKNOWN))
                        continue;

                if (parse_pid(d->d_name, &pid) < 0)
                        continue;

                if (ignore_proc(pid, sig == SIGKILL && !in_initrd()))
                        continue;

                if (sig == SIGKILL) {
                        _cleanup_free_ char *s = NULL;

                        get_process_comm(pid, &s);
                        log_notice("Sending SIGKILL to PID "PID_FMT" (%s).", pid, strna(s));
                }

                if (kill(pid, sig) >= 0) {
                        n_killed++;
                        if (pids) {
                                r = set_put(pids, PID_TO_PTR(pid));
                                if (r < 0)
                                        log_oom();
                        }
                } else if (errno != ENOENT)
                        log_warning_errno(errno, "Could not kill %d: %m", pid);

                if (send_sighup) {
                        /* Optionally, also send a SIGHUP signal, but
                        only if the process has a controlling
                        tty. This is useful to allow handling of
                        shells which ignore SIGTERM but react to
                        SIGHUP. We do not send this to processes that
                        have no controlling TTY since we don't want to
                        trigger reloads of daemon processes. Also we
                        make sure to only send this after SIGTERM so
                        that SIGTERM is always first in the queue. */

                        if (get_ctty_devnr(pid, NULL) >= 0)
                                /* it's OK if the process is gone, just ignore the result */
                                (void) kill(pid, SIGHUP);
                }
        }

        return n_killed;
}

int broadcast_signal(int sig, bool wait_for_exit, bool send_sighup, usec_t timeout) {
        int n_children_left;
        sigset_t mask, oldmask;
        _cleanup_set_free_ Set *pids = NULL;

        /* Send the specified signal to all remaining processes, if not excluded by ignore_proc().
         * Return:
         *  - The number of processes still "alive" after the timeout (that should have been killed)
         *    if the function needs to wait for the end of the processes (wait_for_exit).
         *  - Otherwise, the number of processes to which the specified signal was sent */

        if (wait_for_exit)
                pids = set_new(NULL);

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        if (kill(-1, SIGSTOP) < 0 && errno != ESRCH)
                log_warning_errno(errno, "kill(-1, SIGSTOP) failed: %m");

        n_children_left = killall(sig, pids, send_sighup);

        if (kill(-1, SIGCONT) < 0 && errno != ESRCH)
                log_warning_errno(errno, "kill(-1, SIGCONT) failed: %m");

        if (wait_for_exit && n_children_left > 0)
                n_children_left = wait_for_children(pids, &mask, timeout);

        assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);

        return n_children_left;
}
