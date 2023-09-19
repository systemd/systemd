/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "fd-util.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"

int pidref_set_pid(PidRef *pidref, pid_t pid) {
        int fd;

        assert(pidref);

        if (pid < 0)
                return -ESRCH;
        if (pid == 0)
                pid = getpid_cached();

        fd = pidfd_open(pid, 0);
        if (fd < 0) {
                /* Graceful fallback in case the kernel doesn't support pidfds or is out of fds */
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno) && !ERRNO_IS_RESOURCE(errno))
                        return -errno;

                fd = -EBADF;
        }

        *pidref = (PidRef) {
                .fd = fd,
                .pid = pid,
        };

        return 0;
}

int pidref_set_pidstr(PidRef *pidref, const char *pid) {
        pid_t nr;
        int r;

        assert(pidref);

        r = parse_pid(pid, &nr);
        if (r < 0)
                return r;

        return pidref_set_pid(pidref, nr);
}

int pidref_set_pidfd(PidRef *pidref, int fd) {
        int r;

        assert(pidref);

        if (fd < 0)
                return -EBADF;

        int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0) {
                pid_t pid;

                if (!ERRNO_IS_RESOURCE(errno))
                        return -errno;

                /* Graceful fallback if we are out of fds */
                r = pidfd_get_pid(fd, &pid);
                if (r < 0)
                        return r;

                *pidref = PIDREF_MAKE_FROM_PID(pid);
                return 0;
        }

        return pidref_set_pidfd_consume(pidref, fd_copy);
}

int pidref_set_pidfd_take(PidRef *pidref, int fd) {
        pid_t pid;
        int r;

        assert(pidref);

        if (fd < 0)
                return -EBADF;

        r = pidfd_get_pid(fd, &pid);
        if (r < 0)
                return r;

        *pidref = (PidRef) {
                .fd = fd,
                .pid = pid,
        };

        return 0;
}

int pidref_set_pidfd_consume(PidRef *pidref, int fd) {
        int r;

        r = pidref_set_pidfd_take(pidref, fd);
        if (r < 0)
                safe_close(fd);

        return r;
}

void pidref_done(PidRef *pidref) {
        assert(pidref);

        *pidref = (PidRef) {
                .fd = safe_close(pidref->fd),
        };
}

int pidref_kill(PidRef *pidref, int sig) {

        if (!pidref)
                return -ESRCH;

        if (pidref->fd >= 0)
                return RET_NERRNO(pidfd_send_signal(pidref->fd, sig, NULL, 0));

        if (pidref->pid > 0)
                return RET_NERRNO(kill(pidref->pid, sig));

        return -ESRCH;
}

int pidref_kill_and_sigcont(PidRef *pidref, int sig) {
        int r;

        r = pidref_kill(pidref, sig);
        if (r < 0)
                return r;

        if (!IN_SET(sig, SIGCONT, SIGKILL))
                (void) pidref_kill(pidref, SIGCONT);

        return 0;
}

int pidref_sigqueue(PidRef *pidref, int sig, int value) {

        if (!pidref)
                return -ESRCH;

        if (pidref->fd >= 0) {
                siginfo_t si;

                /* We can't use structured initialization here, since the structure contains various unions
                 * and these fields lie in overlapping (carefully aligned) unions that LLVM is allergic to
                 * allow assignments to */
                zero(si);
                si.si_signo = sig;
                si.si_code = SI_QUEUE;
                si.si_pid = getpid_cached();
                si.si_uid = getuid();
                si.si_value.sival_int = value;

                return RET_NERRNO(pidfd_send_signal(pidref->fd, sig, &si, 0));
        }

        if (pidref->pid > 0)
                return RET_NERRNO(sigqueue(pidref->pid, sig, (const union sigval) { .sival_int = value }));

        return -ESRCH;
}
