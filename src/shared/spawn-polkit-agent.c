/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>

#include "log.h"
#include "util.h"
#include "process-util.h"
#include "spawn-polkit-agent.h"

#ifdef ENABLE_POLKIT
static pid_t agent_pid = 0;

int polkit_agent_open(void) {
        int r;
        int pipe_fd[2];
        char notify_fd[DECIMAL_STR_MAX(int) + 1];

        if (agent_pid > 0)
                return 0;

        /* We check STDIN here, not STDOUT, since this is about input,
         * not output */
        if (!isatty(STDIN_FILENO))
                return 0;

        if (pipe2(pipe_fd, 0) < 0)
                return -errno;

        xsprintf(notify_fd, "%i", pipe_fd[1]);

        r = fork_agent(&agent_pid,
                       &pipe_fd[1], 1,
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
        kill(agent_pid, SIGTERM);
        kill(agent_pid, SIGCONT);
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
