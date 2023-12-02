/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "constants.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "initrd-util.h"
#include "killall.h"
#include "parse-util.h"
#include "process-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"

static bool argv_has_at(pid_t pid) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        char c = 0;

        p = procfs_file_alloca(pid, "cmdline");
        f = fopen(p, "re");
        if (!f) {
                log_debug_errno(errno, "Failed to open %s, ignoring: %m", p);
                return true; /* not really, but has the desired effect */
        }

        /* Try to read the first character of the command line. If the cmdline is empty (which might be the case for
         * kernel threads but potentially also other stuff), this line won't do anything, but we don't care much, as
         * actual kernel threads are already filtered out above. */
        (void) fread(&c, 1, 1, f);

        /* Processes with argv[0][0] = '@' we ignore from the killing spree.
         *
         * https://systemd.io/ROOT_STORAGE_DAEMONS */
        return c == '@';
}

static bool is_survivor_cgroup(const PidRef *pid) {
        _cleanup_free_ char *cgroup_path = NULL;
        int r;

        assert(pidref_is_set(pid));

        r = cg_pidref_get_path(/* root= */ NULL, pid, &cgroup_path);
        if (r < 0) {
                log_warning_errno(r, "Failed to get cgroup path of process " PID_FMT ", ignoring: %m", pid->pid);
                return false;
        }

        r = cg_get_xattr_bool(cgroup_path, "user.survive_final_kill_signal");
        /* user xattr support was added to kernel v5.7, try with the trusted namespace as a fallback */
        if (ERRNO_IS_NEG_XATTR_ABSENT(r))
                r = cg_get_xattr_bool(cgroup_path, "trusted.survive_final_kill_signal");
        if (r < 0 && !ERRNO_IS_NEG_XATTR_ABSENT(r))
                log_debug_errno(r,
                                "Failed to get survive_final_kill_signal xattr of %s, ignoring: %m",
                                cgroup_path);

        return r > 0;
}

static bool ignore_proc(const PidRef *pid, bool warn_rootfs) {
        uid_t uid;
        int r;

        assert(pidref_is_set(pid));

        /* We are PID 1, let's not commit suicide */
        if (pid->pid == 1)
                return true;

        /* Ignore kernel threads */
        r = pidref_is_kernel_thread(pid);
        if (r != 0)
                return true; /* also ignore processes where we can't determine this */

        /* Ignore processes that are part of a cgroup marked with the user.survive_final_kill_signal xattr */
        if (is_survivor_cgroup(pid))
                return true;

        r = pidref_get_uid(pid, &uid);
        if (r < 0)
                return true; /* not really, but better safe than sorry */

        /* Non-root processes otherwise are always subject to be killed */
        if (uid != 0)
                return false;

        if (!argv_has_at(pid->pid))
                return false;

        if (warn_rootfs &&
            pid_from_same_root_fs(pid->pid) > 0) {

                _cleanup_free_ char *comm = NULL;

                (void) pidref_get_comm(pid, &comm);

                log_notice("Process " PID_FMT " (%s) has been marked to be excluded from killing. It is "
                           "running from the root file system, and thus likely to block re-mounting of the "
                           "root file system to read-only. Please consider moving it into an initrd file "
                           "system instead.", pid->pid, strna(comm));
        }

        return true;
}

static void log_children_no_yet_killed(Set *pids) {
        _cleanup_free_ char *lst_child = NULL;
        void *p;
        int r;

        SET_FOREACH(p, pids) {
                _cleanup_free_ char *s = NULL;

                if (pid_get_comm(PTR_TO_PID(p), &s) >= 0)
                        r = strextendf(&lst_child, ", " PID_FMT " (%s)", PTR_TO_PID(p), s);
                else
                        r = strextendf(&lst_child, ", " PID_FMT, PTR_TO_PID(p));
                if (r < 0)
                        return (void) log_oom_warning();
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
                SET_FOREACH(p, pids) {

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
        int n_killed = 0, r;

        /* Send the specified signal to all remaining processes, if not excluded by ignore_proc().
         * Returns the number of processes to which the specified signal was sent */

        r = proc_dir_open(&dir);
        if (r < 0)
                return log_warning_errno(r, "opendir(/proc) failed: %m");

        for (;;) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                r = proc_dir_read_pidref(dir, &pidref);
                if (r < 0)
                        return log_warning_errno(r, "Failed to enumerate /proc: %m");
                if (r == 0)
                        break;

                if (ignore_proc(&pidref, sig == SIGKILL && !in_initrd()))
                        continue;

                if (sig == SIGKILL) {
                        _cleanup_free_ char *s = NULL;

                        (void) pidref_get_comm(&pidref, &s);
                        log_notice("Sending SIGKILL to PID "PID_FMT" (%s).", pidref.pid, strna(s));
                }

                r = pidref_kill(&pidref, sig);
                if (r < 0) {
                        if (errno != -ESRCH)
                                log_warning_errno(errno, "Could not kill " PID_FMT ", ignoring: %m", pidref.pid);
                } else {
                        n_killed++;
                        if (pids) {
                                r = set_put(pids, PID_TO_PTR(pidref.pid));
                                if (r < 0)
                                        (void) log_oom_warning();
                        }
                }

                if (send_sighup) {
                        /* Optionally, also send a SIGHUP signal, but only if the process has a controlling
                         * tty. This is useful to allow handling of shells which ignore SIGTERM but react to
                         * SIGHUP. We do not send this to processes that have no controlling TTY since we
                         * don't want to trigger reloads of daemon processes. Also we make sure to only send
                         * this after SIGTERM so that SIGTERM is always first in the queue. */

                        if (get_ctty_devnr(pidref.pid, NULL) >= 0)
                                /* it's OK if the process is gone, just ignore the result */
                                (void) pidref_kill(&pidref, SIGHUP);
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
