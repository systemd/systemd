/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_PIDFD_OPEN
#include <sys/pidfd.h>
#endif

#include "errno-util.h"
#include "fd-util.h"
#include "missing_magic.h"
#include "missing_syscall.h"
#include "missing_wait.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"

static int pidfd_inode_ids_supported(void) {
        static int cached = -1;

        if (cached >= 0)
                return cached;

        _cleanup_close_ int fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return (cached = false);

                return -errno;
        }

        return (cached = fd_is_fs_type(fd, PID_FS_MAGIC));
}

int pidref_acquire_pidfd_id(PidRef *pidref) {
        int r;

        assert(pidref);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->fd < 0)
                return -ENOMEDIUM;

        if (pidref->fd_id > 0)
                return 0;

        r = pidfd_inode_ids_supported();
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        struct stat st;

        if (fstat(pidref->fd, &st) < 0)
                return log_debug_errno(errno, "Failed to get inode number of pidfd for pid " PID_FMT ": %m",
                                       pidref->pid);

        pidref->fd_id = (uint64_t) st.st_ino;
        return 0;
}

bool pidref_equal(PidRef *a, PidRef *b) {

        if (pidref_is_set(a)) {
                if (!pidref_is_set(b))
                        return false;

                if (a->pid != b->pid)
                        return false;

                /* Try to compare pidfds using their inode numbers. This way we can ensure that we don't
                 * spuriously consider two PidRefs equal if the pid has been reused once. Note that we
                 * ignore all errors here, not only EOPNOTSUPP, as fstat() might fail due to many reasons. */
                if (pidref_acquire_pidfd_id(a) < 0 || pidref_acquire_pidfd_id(b) < 0)
                        return true;

                return a->fd_id == b->fd_id;
        }

        return !pidref_is_set(b);
}

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
                        return log_debug_errno(errno, "Failed to open pidfd for pid " PID_FMT ": %m", pid);

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

int pidref_set_parent(PidRef *ret) {
        _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;
        pid_t ppid;
        int r;

        assert(ret);

        /* Acquires a pidref to our parent process. Deals with the fact that parent processes might exit, and
         * we get reparented to other processes, with our old parent's PID already being recycled. */

        ppid = getppid();
        for (;;) {
                r = pidref_set_pid(&parent, ppid);
                if (r < 0)
                        return r;

                if (parent.fd < 0) /* If pidfds are not available, then we are done */
                        break;

                pid_t now_ppid = getppid();
                if (now_ppid == ppid) /* If our ppid is still the same, then we are done */
                        break;

                /* Otherwise let's try again with the new ppid */
                ppid = now_ppid;
                pidref_done(&parent);
        }

        *ret = TAKE_PIDREF(parent);
        return 0;
}

void pidref_done(PidRef *pidref) {
        assert(pidref);

        *pidref = (PidRef) {
                .fd = safe_close(pidref->fd),
        };
}

PidRef* pidref_free(PidRef *pidref) {
        /* Regularly, this is an embedded structure. But sometimes we want it on the heap too */
        if (!pidref)
                return NULL;

        pidref_done(pidref);
        return mfree(pidref);
}

int pidref_copy(const PidRef *pidref, PidRef *dest) {
        _cleanup_close_ int dup_fd = -EBADF;
        pid_t dup_pid = 0;

        /* If NULL is passed we'll generate a PidRef that refers to no process. This makes it easy to
         * copy pidref fields that might or might not reference a process yet. */

        assert(dest);

        if (pidref) {
                if (pidref->fd >= 0) {
                        dup_fd = fcntl(pidref->fd, F_DUPFD_CLOEXEC, 3);
                        if (dup_fd < 0) {
                                if (!ERRNO_IS_RESOURCE(errno))
                                        return -errno;

                                dup_fd = -EBADF;
                        }
                }

                if (pidref->pid > 0)
                        dup_pid = pidref->pid;
        }

        *dest = (PidRef) {
                .fd = TAKE_FD(dup_fd),
                .pid = dup_pid,
        };

        return 0;
}

int pidref_dup(const PidRef *pidref, PidRef **ret) {
        _cleanup_(pidref_freep) PidRef *dup_pidref = NULL;
        int r;

        /* Allocates a new PidRef on the heap, making it a copy of the specified pidref. This does not try to
         * acquire a pidfd if we don't have one yet! */

        assert(ret);

        dup_pidref = newdup(PidRef, &PIDREF_NULL, 1);
        if (!dup_pidref)
                return -ENOMEM;

        r = pidref_copy(pidref, dup_pidref);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dup_pidref);
        return 0;
}

int pidref_new_from_pid(pid_t pid, PidRef **ret) {
        _cleanup_(pidref_freep) PidRef *n = NULL;
        int r;

        assert(ret);

        if (pid < 0)
                return -ESRCH;

        n = new(PidRef, 1);
        if (!n)
                return -ENOMEM;

        *n = PIDREF_NULL;

        r = pidref_set_pid(n, pid);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(n);
        return 0;
}

int pidref_kill(const PidRef *pidref, int sig) {

        if (!pidref)
                return -ESRCH;

        if (pidref->fd >= 0)
                return RET_NERRNO(pidfd_send_signal(pidref->fd, sig, NULL, 0));

        if (pidref->pid > 0)
                return RET_NERRNO(kill(pidref->pid, sig));

        return -ESRCH;
}

int pidref_kill_and_sigcont(const PidRef *pidref, int sig) {
        int r;

        r = pidref_kill(pidref, sig);
        if (r < 0)
                return r;

        if (!IN_SET(sig, SIGCONT, SIGKILL))
                (void) pidref_kill(pidref, SIGCONT);

        return 0;
}

int pidref_sigqueue(const PidRef *pidref, int sig, int value) {

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

int pidref_verify(const PidRef *pidref) {
        int r;

        /* This is a helper that is supposed to be called after reading information from procfs via a
         * PidRef. It ensures that the PID we track still matches the PIDFD we pin. If this value differs
         * after a procfs read, we might have read the data from a recycled PID. */

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->pid == 1)
                return 1; /* PID 1 can never go away, hence never be recycled to a different process → return 1 */

        if (pidref->fd < 0)
                return 0; /* If we don't have a pidfd we cannot validate it, hence we assume it's all OK → return 0 */

        r = pidfd_verify_pid(pidref->fd, pidref->pid);
        if (r < 0)
                return r;

        return 1; /* We have a pidfd and it still points to the PID we have, hence all is *really* OK → return 1 */
}

bool pidref_is_self(const PidRef *pidref) {
        if (!pidref)
                return false;

        return pidref->pid == getpid_cached();
}

int pidref_wait(const PidRef *pidref, siginfo_t *ret, int options) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->pid == 1 || pidref->pid == getpid_cached())
                return -ECHILD;

        siginfo_t si = {};

        if (pidref->fd >= 0) {
                r = RET_NERRNO(waitid(P_PIDFD, pidref->fd, &si, options));
                if (r >= 0) {
                        if (ret)
                                *ret = si;
                        return r;
                }
                if (r != -EINVAL) /* P_PIDFD was added in kernel 5.4 only */
                        return r;
        }

        r = RET_NERRNO(waitid(P_PID, pidref->pid, &si, options));
        if (r >= 0 && ret)
                *ret = si;
        return r;
}

int pidref_wait_for_terminate(const PidRef *pidref, siginfo_t *ret) {
        int r;

        for (;;) {
                r = pidref_wait(pidref, ret, WEXITED);
                if (r != -EINTR)
                        return r;
        }
}

static void pidref_hash_func(const PidRef *pidref, struct siphash *state) {
        siphash24_compress_typesafe(pidref->pid, state);
}

static int pidref_compare_func(const PidRef *a, const PidRef *b) {
        return CMP(a->pid, b->pid);
}

DEFINE_HASH_OPS(pidref_hash_ops, PidRef, pidref_hash_func, pidref_compare_func);

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(pidref_hash_ops_free,
                                    PidRef, pidref_hash_func, pidref_compare_func,
                                    pidref_free);
