/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include "async-close.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "process-util.h"

/* We encode the fd to close in the userdata pointer as an unsigned value. The highest bit indicates whether
 * we need to fork again */
#define NEED_DOUBLE_FORK (1U << (sizeof(unsigned) * 8 - 1))

static int close_func(void *p) {
        unsigned v = PTR_TO_UINT(p);

        (void) proc_set_comm("(sd-close)");

        /* Note: 💣 This function is invoked in a child process created via glibc's clone() wrapper. In such
         *       children memory allocation is not allowed, since glibc does not release malloc mutexes in
         *       clone() 💣 */

        if (v & NEED_DOUBLE_FORK) {
                pid_t pid;

                v &= ~NEED_DOUBLE_FORK;

                /* This inner child will be reparented to the subreaper/PID 1. Here we turn on SIGCHLD, so
                 * that the reaper knows when it's time to reap. */
                pid = clone_with_nested_stack(close_func, SIGCHLD|CLONE_FILES, UINT_TO_PTR(v));
                if (pid >= 0)
                        return 0;
        }

        close((int) v); /* no assert() here, we are in the child and the result would be eaten up anyway */
        return 0;
}

int asynchronous_close(int fd) {
        unsigned v;
        pid_t pid;
        int r;

        /* This is supposed to behave similar to safe_close(), but actually invoke close() asynchronously, so
         * that it will never block. Ideally the kernel would have an API for this, but it doesn't, so we
         * work around it, and hide this as a far away as we can.
         *
         * It is important to us that we don't use threads (via glibc pthread) in PID 1, hence we'll do a
         * minimal subprocess instead which shares our fd table via CLONE_FILES. */

        if (fd < 0)
                return -EBADF; /* already invalid */

        PROTECT_ERRNO;

        v = (unsigned) fd;

        /* We want to fork off a process that is automatically reaped. For that we'd usually double-fork. But
         * we can optimize this a bit: if we are PID 1 or a subreaper anyway (the systemd service manager
         * process qualifies as this), we can avoid the double forking, since the double forked process would
         * be reparented back to us anyway. */
        r = is_reaper_process();
        if (r < 0)
                log_debug_errno(r, "Cannot determine if we are a reaper process, assuming we are not: %m");
        if (r <= 0)
                v |= NEED_DOUBLE_FORK;

        pid = clone_with_nested_stack(close_func, CLONE_FILES | ((v & NEED_DOUBLE_FORK) ? 0 : SIGCHLD), UINT_TO_PTR(v));
        if (pid < 0)
                safe_close(fd); /* local fallback */
        else if (v & NEED_DOUBLE_FORK) {

                /* Reap the intermediate child. Key here is that we specify __WCLONE, since we didn't ask for
                 * any signal to be sent to us on process exit, and otherwise waitid() would refuse waiting
                 * then.
                 *
                 * We usually prefer calling waitid(), but before kernel 4.7 it didn't support __WCLONE while
                 * waitpid() did. Hence let's use waitpid() here, it's good enough for our purposes here. */
                for (;;)
                        if (waitpid(pid, NULL, __WCLONE) >= 0 || errno != EINTR)
                                break;
        }

        return -EBADF; /* return an invalidated fd */
}

void asynchronous_close_many(const int fds[], size_t n_fds) {
        assert(fds || n_fds == 0);

        FOREACH_ARRAY(i, fds, n_fds)
                asynchronous_close(*i);
}
