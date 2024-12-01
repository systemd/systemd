/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "exec-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "polkit-agent.h"
#include "process-util.h"
#include "stdio-util.h"
#include "time-util.h"

#if ENABLE_POLKIT
static pid_t agent_pid = 0;

int polkit_agent_open(void) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        char notify_fd[DECIMAL_STR_MAX(int) + 1];
        int r;

        if (agent_pid > 0)
                return 0;

        /* Clients that run as root don't need to activate/query polkit */
        if (geteuid() == 0)
                return 0;

        r = shall_fork_agent();
        if (r <= 0)
                return r;

        if (pipe2(pipe_fd, 0) < 0)
                return -errno;

        xsprintf(notify_fd, "%i", pipe_fd[1]);

        r = fork_agent("(polkit-agent)",
                       &pipe_fd[1],
                       1,
                       &agent_pid,
                       POLKIT_AGENT_BINARY_PATH,
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

        if (agent_pid <= 0)
                return;

        /* Inform agent that we are done */
        sigterm_wait(TAKE_PID(agent_pid));
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
