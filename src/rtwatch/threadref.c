/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "threadref.h"

static int threadref_gone(const ThreadRef *t) {
        int r;

        assert(t);

        /* Called when we noticed that the thread is gone. Distinguishes "process is gone" (-ESRCH) from
         * "thread is gone or not part of the process" (-ENXIO). Other errors are propagated as-is. */

        r = pidref_verify(&t->process);
        if (r < 0)
                return r; /* -ESRCH if the process is gone, but also any unexpected error */

        return -ENXIO;
}

static int threadref_verify_membership(const ThreadRef *t) {
        char path[STRLEN("/proc//task/") + DECIMAL_STR_MAX(pid_t) * 2];
        int r;

        assert(threadref_is_set(t));

        /* Checks that the TID is part of the process. If we have a thread pidfd, we can just ask the kernel
         * which thread group the pinned thread belongs to. */
        if (t->thread_pidfd >= 0) {
                struct pidfd_info info = { .mask = PIDFD_INFO_PID };

                r = pidfd_get_info(t->thread_pidfd, &info);
                if (r == -ESRCH)
                        return threadref_gone(t);
                if (r >= 0) {
                        assert(FLAGS_SET(info.mask, PIDFD_INFO_PID));
                        return (pid_t) info.tgid == t->process.pid ? 0 : -ENXIO;
                }
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return r;
        }

        /* Otherwise, check via procfs. Note that the procfs lookup is not race-free on its own: we have to
         * check afterwards that both the process and the thread still exist (and hence the PID and TID
         * haven't been recycled), which threadref_verify() does. */

        xsprintf(path, "/proc/" PID_FMT "/task/" PID_FMT, t->process.pid, t->thread_id);
        if (access(path, F_OK) < 0) {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to check if '%s' exists: %m", path);

                return threadref_gone(t);
        }

        return 0;
}

int threadref_verify(const ThreadRef *t) {
        int r;

        if (!threadref_is_set(t))
                return -ESRCH;

        r = threadref_verify_membership(t);
        if (r < 0)
                return r;

        /* Now that we know the TID was part of the PID, make sure neither got recycled in the meantime. As
         * long as the thread is alive, its TID cannot be reused, hence if the thread pidfd still refers to
         * the TID, the procfs check above was about the right thread. */
        if (t->thread_pidfd >= 0) {
                r = pidfd_verify_pid(t->thread_pidfd, t->thread_id);
                if (r == -ESRCH)
                        return threadref_gone(t);
                if (r < 0)
                        return r;
        }

        r = pidref_verify(&t->process);
        if (r < 0)
                return r;

        return 0;
}

int threadref_set_full(ThreadRef *t, const PidRef *process, pid_t tid, uint64_t pidfd_id) {
        _cleanup_(threadref_done) ThreadRef n = THREADREF_NULL;
        int r;

        assert(t);
        assert(tid >= 0);

        if (!pidref_is_set(process))
                return -ESRCH;
        if (pidref_is_remote(process))
                return -EREMOTE;

        r = pidref_copy(process, &n.process);
        if (r < 0)
                return r;

        n.thread_id = tid == 0 ? process->pid : tid;

        /* First pin the thread, then check that it is part of the process, see threadref_verify() */
        n.thread_pidfd = pidfd_open(n.thread_id, PIDFD_THREAD);
        if (n.thread_pidfd < 0) {
                if (errno == ESRCH)
                        return threadref_gone(&n);

                /* PIDFD_THREAD is supported since kernel v6.9 (64bef697d33b75fc06c5789b3f8108680271529f),
                 * gracefully fall back to operating without a thread pidfd on older kernels, and if we
                 * ran out of fds. */
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL && !ERRNO_IS_RESOURCE(errno))
                        return log_debug_errno(errno, "Failed to open pidfd for thread " PID_FMT ": %m", n.thread_id);

                n.thread_pidfd = -EBADF;
        }

        r = threadref_verify(&n);
        if (r < 0)
                return r;

        if (pidfd_id > 0) {
                /* If the caller expects a specific thread pidfd inode number, check that the TID was not
                 * recycled. We can only do that if we have a thread pidfd, of course. */
                r = threadref_acquire_pidfd_id(&n);
                if (r == -ENOMEDIUM || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Not validating thread pidfd inode number of thread " PID_FMT ", because operating without thread pidfd.", n.thread_id);
                else if (r < 0)
                        return r;
                else if (n.thread_pidfd_id != pidfd_id)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                                               "Thread " PID_FMT " does not have the expected pidfd inode number, refusing.", n.thread_id);
        }

        *t = TAKE_THREADREF(n);
        return 0;
}

int threadref_acquire_pidfd_id(ThreadRef *t) {
        int r;

        assert(t);

        if (!threadref_is_set(t))
                return -ESRCH;

        if (t->thread_pidfd < 0)
                return -ENOMEDIUM;

        if (t->thread_pidfd_id > 0)
                return 0;

        r = pidfd_get_inode_id(t->thread_pidfd, &t->thread_pidfd_id);
        if (r < 0) {
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Failed to get inode number of pidfd for thread " PID_FMT ": %m", t->thread_id);
                return r;
        }

        return 0;
}

void threadref_done(ThreadRef *t) {
        assert(t);

        pidref_done(&t->process);
        t->thread_id = 0;
        t->thread_pidfd = safe_close(t->thread_pidfd);
        t->thread_pidfd_id = 0;
}

int threadref_get_comm(const ThreadRef *t, char **ret) {
        _cleanup_free_ char *comm = NULL;
        int r;

        assert(ret);

        if (!threadref_is_set(t))
                return -ESRCH;

        r = pid_get_thread_comm(t->process.pid, t->thread_id, &comm);
        if (r == -ESRCH)
                return threadref_gone(t);
        if (r < 0)
                return r;

        r = threadref_verify(t);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(comm);
        return 0;
}

bool threadref_equal(ThreadRef *a, ThreadRef *b) {

        /* If this is the very same structure, it definitely refers to the same thread */
        if (a == b)
                return true;

        if (!threadref_is_set(a))
                return !threadref_is_set(b);

        if (!threadref_is_set(b))
                return false;

        if (a->thread_id != b->thread_id)
                return false;

        if (!pidref_equal(&a->process, &b->process))
                return false;

        /* Try to compare the thread pidfds using their inode numbers, so that we don't spuriously consider
         * two ThreadRefs equal if the TID has been reused. If we lack a thread pidfd on either side (i.e.
         * on kernels older than 6.9) we have no way to tell, hence assume they are the same, like
         * pidref_equal() does. */
        if (threadref_acquire_pidfd_id(a) < 0 || threadref_acquire_pidfd_id(b) < 0)
                return true;

        return a->thread_pidfd_id == b->thread_pidfd_id;
}

int threadref_copy(const ThreadRef *t, ThreadRef *ret) {
        _cleanup_(threadref_done) ThreadRef n = THREADREF_NULL;
        int r;

        assert(ret);

        if (!threadref_is_set(t))
                return -ESRCH;

        r = pidref_copy(&t->process, &n.process);
        if (r < 0)
                return r;

        n.thread_id = t->thread_id;

        if (t->thread_pidfd >= 0) {
                n.thread_pidfd = fcntl(t->thread_pidfd, F_DUPFD_CLOEXEC, 3);
                if (n.thread_pidfd < 0)
                        return -errno;

                n.thread_pidfd_id = t->thread_pidfd_id;
        }

        *ret = TAKE_THREADREF(n);
        return 0;
}
