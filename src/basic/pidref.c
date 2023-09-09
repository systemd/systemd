/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "fd-util.h"
#include "missing_syscall.h"
#include "pidref.h"
#include "process-util.h"

int pidref_set_pid(PidRef *pidref, pid_t pid) {
        int fd;

        assert(pidref);

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

int pidref_set_pidfd(PidRef *pidref, int fd) {
        _cleanup_close_ int fd_copy = -EBADF;
        int r;

        fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0) {
                pid_t pid;

                if (!ERRNO_IS_RESOURCE(errno))
                        return -errno;

                /* Graceful fallback if we are out of fds */
                r = pidfd_get_pid(fd, &pid);
                if (r < 0)
                        return r;

                return pidref_set_pid(pidref, pid);
        }

        r = pidref_set_pidfd_take(pidref, fd_copy);
        if (r < 0)
                return r;

        TAKE_FD(fd_copy);
        return 0;
}

int pidref_set_pidfd_take(PidRef *pidref, int fd) {
        pid_t pid;
        int r;

        assert(pidref);

        r = pidfd_get_pid(fd, &pid);
        if (r < 0)
                return r;

        *pidref = (PidRef) {
                .fd = fd,
                .pid = pid,
        };

        return 0;
}

PidRef* pidref_done(PidRef *pidref) {
        if (!pidref)
                return NULL;

        *pidref = (PidRef) {
                .fd = safe_close(pidref->fd),
        };

        return NULL;
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
