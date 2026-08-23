/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "stdio-util.h"

#if ENABLE_POLKIT
static PidRef agent_pidref = PIDREF_NULL;

int polkit_agent_open(void) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        char notify_fd[DECIMAL_STR_MAX(int) + 1];
        int r;

        if (pidref_is_set(&agent_pidref))
                return 0;

        /* Clients that run as root don't need to activate/query polkit */
        if (geteuid() == 0)
                return 0;

        r = shall_fork_agent();
        if (r <= 0)
                return r;

        _cleanup_free_ char *pkttyagent = NULL;
        r = find_executable("pkttyagent", &pkttyagent);
        if (r == -ENOENT) {
                log_debug("pkttyagent binary not available, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether pkttyagent binary exists: %m");

        if (pipe2(pipe_fd, 0) < 0)
                return -errno;

        xsprintf(notify_fd, "%i", pipe_fd[1]);

        r = fork_agent("(polkit-agent)",
                       &pipe_fd[1],
                       1,
                       &agent_pidref,
                       pkttyagent,
                       "--notify-fd", notify_fd,
                       "--fallback");
        if (r < 0)
                return log_error_errno(r, "Failed to fork polkit agent: %m");

        /* Close the writing side, because that's the one for the agent */
        pipe_fd[1] = safe_close(pipe_fd[1]);

        /* Wait until the agent closes the fd */
        (void) fd_wait_for_event(pipe_fd[0], POLLHUP, USEC_INFINITY);

        return 1;
}

void polkit_agent_close(void) {
        /* Inform agent that we are done */
        pidref_done_sigterm_wait(&agent_pidref);
}

#else

int polkit_agent_open(void) {
        return 0;
}

void polkit_agent_close(void) {
}

#endif

int polkit_agent_open_if_enabled(BusTransport transport, bool ask_password) {

        /* Open the polkit agent as a child process if necessary */

        if (transport != BUS_TRANSPORT_LOCAL)
                return 0;

        if (!ask_password)
                return 0;

        return polkit_agent_open();
}
