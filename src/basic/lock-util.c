/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "lock-util.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "path-util.h"
#include "process-util.h"

int make_lock_file_at(int dir_fd, const char *p, int operation, LockFile *ret) {
        _cleanup_close_ int fd = -EBADF, dfd = -EBADF;
        _cleanup_free_ char *t = NULL;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(p);
        assert(IN_SET(operation & ~LOCK_NB, LOCK_EX, LOCK_SH));
        assert(ret);

        if (isempty(p))
                return -EINVAL;

        /* We use UNPOSIX locks as they have nice semantics, and are mostly compatible with NFS. */

        dfd = fd_reopen(dir_fd, O_CLOEXEC|O_PATH|O_DIRECTORY);
        if (dfd < 0)
                return dfd;

        t = strdup(p);
        if (!t)
                return -ENOMEM;

        fd = xopenat_lock_full(dfd,
                               p,
                               O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY,
                               /* xopen_flags = */ 0,
                               0600,
                               LOCK_UNPOSIX,
                               operation);
        if (fd < 0)
                return fd == -EAGAIN ? -EBUSY : fd;

        *ret = (LockFile) {
                .dir_fd = TAKE_FD(dfd),
                .path = TAKE_PTR(t),
                .fd = TAKE_FD(fd),
                .operation = operation,
        };

        return 0;
}

int make_lock_file_for(const char *p, int operation, LockFile *ret) {
        _cleanup_free_ char *fn = NULL, *dn = NULL, *t = NULL;
        int r;

        assert(p);
        assert(ret);

        r = path_extract_filename(p, &fn);
        if (r < 0)
                return r;

        r = path_extract_directory(p, &dn);
        if (r < 0)
                return r;

        t = strjoin(dn, "/.#", fn, ".lck");
        if (!t)
                return -ENOMEM;

        return make_lock_file(t, operation, ret);
}

void release_lock_file(LockFile *f) {
        if (!f)
                return;

        if (f->path) {

                /* If we are the exclusive owner we can safely delete
                 * the lock file itself. If we are not the exclusive
                 * owner, we can try becoming it. */

                if (f->fd >= 0 &&
                    (f->operation & ~LOCK_NB) == LOCK_SH &&
                    unposix_lock(f->fd, LOCK_EX|LOCK_NB) >= 0)
                        f->operation = LOCK_EX|LOCK_NB;

                if ((f->operation & ~LOCK_NB) == LOCK_EX)
                        (void) unlinkat(f->dir_fd, f->path, 0);

                f->path = mfree(f->path);
        }

        f->dir_fd = safe_close(f->dir_fd);
        f->fd = safe_close(f->fd);
        f->operation = 0;
}

static int fcntl_lock(int fd, int operation, bool ofd) {
        int cmd, type, r;

        assert(fd >= 0);

        if (ofd)
                cmd = (operation & LOCK_NB) ? F_OFD_SETLK : F_OFD_SETLKW;
        else
                cmd = (operation & LOCK_NB) ? F_SETLK : F_SETLKW;

        switch (operation & ~LOCK_NB) {
                case LOCK_EX:
                        type = F_WRLCK;
                        break;
                case LOCK_SH:
                        type = F_RDLCK;
                        break;
                case LOCK_UN:
                        type = F_UNLCK;
                        break;
                default:
                        assert_not_reached();
        }

        r = RET_NERRNO(fcntl(fd, cmd, &(struct flock) {
                .l_type = type,
                .l_whence = SEEK_SET,
                .l_start = 0,
                .l_len = 0,
        }));

        /* If we are doing non-blocking operations, treat EACCES/EAGAIN the same as per man page. But if
         * not, propagate EACCES back, as it will likely be due to an LSM denying the operation (for example
         * LXC with AppArmor when running on kernel < 6.2), and in some cases we want to gracefully
         * fallback (e.g.: PrivateNetwork=yes). As per documentation, it's only the non-blocking operation
         * F_SETLK that might return EACCES on some platforms (although the Linux implementation doesn't
         * seem to), as F_SETLKW and F_OFD_SETLKW block so this is not an issue, and F_OFD_SETLK is documented
         * to only return EAGAIN if the lock is already held. */
        if ((operation & LOCK_NB) && r == -EACCES)
                r = -EAGAIN;

        return r;
}

int posix_lock(int fd, int operation) {
        return fcntl_lock(fd, operation, /*ofd=*/ false);
}

int unposix_lock(int fd, int operation) {
        return fcntl_lock(fd, operation, /*ofd=*/ true);
}

void posix_unlockpp(int **fd) {
        assert(fd);

        if (!*fd || **fd < 0)
                return;

        (void) fcntl_lock(**fd, LOCK_UN, /*ofd=*/ false);
        *fd = NULL;
}

void unposix_unlockpp(int **fd) {
        assert(fd);

        if (!*fd || **fd < 0)
                return;

        (void) fcntl_lock(**fd, LOCK_UN, /*ofd=*/ true);
        *fd = NULL;
}

int lock_generic(int fd, LockType type, int operation) {
        assert(fd >= 0);

        switch (type) {
        case LOCK_NONE:
                return 0;
        case LOCK_BSD:
                return RET_NERRNO(flock(fd, operation));
        case LOCK_POSIX:
                return posix_lock(fd, operation);
        case LOCK_UNPOSIX:
                return unposix_lock(fd, operation);
        default:
                assert_not_reached();
        }
}

int lock_generic_with_timeout(int fd, LockType type, int operation, usec_t timeout) {
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        int r;

        assert(fd >= 0);

        /* A version of lock_generic(), but with a timeout. We do this in a child process, since the kernel
         * APIs natively don't support a timeout. We set a SIGALRM timer that will kill the child after the
         * timeout is hit. Returns -ETIMEDOUT if the timeout is hit, and 0 on success.
         *
         * This only works for BSD and UNPOSIX locks, as only those are fd-bound, and hence can be acquired
         * from any process that has access to the fd. POSIX locks OTOH are process-bound, and hence if we'd
         * acquire them in a child process they'd remain unlocked in the parent. */

        if (type == LOCK_NONE)
                return 0;
        if (!IN_SET(type, LOCK_BSD, LOCK_UNPOSIX)) /* Not for POSIX locks, see above. */
                return -EOPNOTSUPP;

        /* First, try without forking anything off */
        r = lock_generic(fd, type, operation | (timeout == USEC_INFINITY ? 0 : LOCK_NB));
        if (r != -EAGAIN || timeout == 0 || FLAGS_SET(operation, LOCK_NB))
                return r;

        /* If that didn't work, try with a child */

        r = safe_fork("(sd-flock)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to flock block device in child process: %m");
        if (r == 0) {
                struct sigevent sev = {
                        .sigev_notify = SIGEV_SIGNAL,
                        .sigev_signo = SIGALRM,
                };
                timer_t id;

                if (timer_create(CLOCK_MONOTONIC, &sev, &id) < 0) {
                        log_error_errno(errno, "Failed to allocate CLOCK_MONOTONIC timer: %m");
                        _exit(EXIT_FAILURE);
                }

                struct itimerspec its = {};
                timespec_store(&its.it_value, timeout);

                if (timer_settime(id, /* flags= */ 0, &its, NULL) < 0) {
                        log_error_errno(errno, "Failed to start CLOCK_MONOTONIC timer: %m");
                        _exit(EXIT_FAILURE);
                }

                if (lock_generic(fd, type, operation) < 0) {
                        log_error_errno(errno, "Unable to get an exclusive lock on the device: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        siginfo_t status;
        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return r;

        TAKE_PID(pid);

        switch (status.si_code) {

        case CLD_EXITED:
                if (status.si_status != EXIT_SUCCESS)
                        return -EPROTO;

                return 0;

        case CLD_KILLED:
                if (status.si_status == SIGALRM)
                        return -ETIMEDOUT;

                _fallthrough_;

        case CLD_DUMPED:
                return -EPROTO;

        default:
                assert_not_reached();
        }
}
