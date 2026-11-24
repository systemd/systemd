/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "async.h"
#include "log.h"
#include "process-util.h"
#include "rm-rf.h"
#include "signal-util.h"

int asynchronous_sync(PidRef *ret_pid) {
        int r;

        /* This forks off an invocation of fork() as a child process, in order to initiate synchronization to
         * disk. Note that we implement this as helper process rather than thread as we don't want the sync() to hang our
         * original process ever, and a thread would do that as the process can't exit with threads hanging in blocking
         * syscalls. */

        r = pidref_safe_fork("(sd-sync)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|(ret_pid ? 0 : FORK_DETACH), ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process */
                sync();
                _exit(EXIT_SUCCESS);
        }

        return 0;
}

int asynchronous_fsync(int fd, PidRef *ret_pid) {
        int r;

        assert(fd >= 0);
        /* Same as asynchronous_sync() above, but calls fsync() on a specific fd */

        r = pidref_safe_fork_full(
                        "(sd-fsync)",
                        /* stdio_fds= */ NULL,
                        /* except_fds= */ &fd,
                        /* n_except_fds= */ 1,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|(ret_pid ? 0 : FORK_DETACH),
                        ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process */
                (void) fsync(fd);
                _exit(EXIT_SUCCESS);
        }

        return 0;
}

int asynchronous_rm_rf(const char *p, RemoveFlags flags) {
        int r;

        assert(p);

        /* Forks off a child that destroys the specified path. This will be best effort only, i.e. the child
         * will attempt to do its thing, but we won't wait for it or check its success. */

        r = pidref_safe_fork("(sd-rmrf)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DETACH, /* ret= */ NULL);
        if (r != 0)
                return r;

        /* Child */

        /* Let's block SIGTERM here, to grant the operation more time on e.g. final killing spree
         * during shutdown. If this gets stalled pid1 would eventually send SIGKILL to us. */
        BLOCK_SIGNALS(SIGTERM);

        r = rm_rf(p, flags);
        if (r < 0) {
                log_debug_errno(r, "Failed to rm -rf '%s', ignoring: %m", p);
                _exit(EXIT_FAILURE); /* This is a detached process, hence no one really cares, but who knows
                                      * maybe it's good for debugging/tracing to return an exit code
                                      * indicative of our failure here. */
        }

        _exit(EXIT_SUCCESS);
}
