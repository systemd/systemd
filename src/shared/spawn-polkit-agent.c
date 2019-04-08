/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "spawn-polkit-agent.h"
#include "stdio-util.h"
#include "time-util.h"
#include "util.h"

#if ENABLE_POLKIT
static pid_t agent_pid = 0;

int polkit_agent_open(void) {
        char notify_fd[DECIMAL_STR_MAX(int) + 1];
        int pipe_fd[2], r;

        if (agent_pid > 0)
                return 0;

        /* Clients that run as root don't need to activate/query polkit */
        if (geteuid() == 0)
                return 0;

        /* We check STDIN here, not STDOUT, since this is about input, not output */
        if (!isatty(STDIN_FILENO))
                return 0;

        if (!is_main_thread())
                return -EPERM;

        if (pipe2(pipe_fd, 0) < 0)
                return -errno;

        xsprintf(notify_fd, "%i", pipe_fd[1]);

        r = fork_agent("(polkit-agent)",
                       &pipe_fd[1], 1,
                       &agent_pid,
                       POLKIT_AGENT_BINARY_PATH,
                       POLKIT_AGENT_BINARY_PATH, "--notify-fd", notify_fd, "--fallback", NULL);

        /* Close the writing side, because that's the one for the agent */
        safe_close(pipe_fd[1]);

        if (r < 0)
                log_error_errno(r, "Failed to fork TTY ask password agent: %m");
        else
                /* Wait until the agent closes the fd */
                fd_wait_for_event(pipe_fd[0], POLLHUP, USEC_INFINITY);

        safe_close(pipe_fd[0]);

        return r;
}

void polkit_agent_close(void) {

        if (agent_pid <= 0)
                return;

        /* Inform agent that we are done */
        (void) kill_and_sigcont(agent_pid, SIGTERM);
        (void) wait_for_terminate(agent_pid, NULL);
        agent_pid = 0;
}

#else

int polkit_agent_open(void) {
        return 0;
}

void polkit_agent_close(void) {
}

#endif
