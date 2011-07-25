/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>

#include "log.h"
#include "util.h"
#include "spawn-agent.h"

static pid_t agent_pid = 0;

void agent_open(void) {
        pid_t parent_pid;

        if (agent_pid > 0)
                return;

        /* We check STDIN here, not STDOUT, since this is about input,
         * not output */
        if (!isatty(STDIN_FILENO))
                return;

        parent_pid = getpid();

        /* Spawns a temporary TTY agent, making sure it goes away when
         * we go away */

        agent_pid = fork();
        if (agent_pid < 0) {
                log_error("Failed to fork agent: %m");
                return;
        }

        if (agent_pid == 0) {
                /* In the child */

                int fd;
                bool stdout_is_tty, stderr_is_tty;

                /* Make sure the agent goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                /* Don't leak fds to the agent */
                close_all_fds(NULL, 0);

                stdout_is_tty = isatty(STDOUT_FILENO);
                stderr_is_tty = isatty(STDERR_FILENO);

                if (!stdout_is_tty || !stderr_is_tty) {
                        /* Detach from stdout/stderr. and reopen
                         * /dev/tty for them. This is important to
                         * ensure that when systemctl is started via
                         * popen() or a similar call that expects to
                         * read EOF we actually do generate EOF and
                         * not delay this indefinitely by because we
                         * keep an unused copy of stdin around. */
                        fd = open("/dev/tty", O_WRONLY);
                        if (fd < 0) {
                                log_error("Failed to open /dev/tty: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (!stdout_is_tty)
                                dup2(fd, STDOUT_FILENO);

                        if (!stderr_is_tty)
                                dup2(fd, STDERR_FILENO);

                        if (fd > 2)
                                close(fd);
                }

                execl(SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH, SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH, "--watch", NULL);

                log_error("Unable to execute agent: %m");
                _exit(EXIT_FAILURE);
        }
}

void agent_close(void) {

        if (agent_pid <= 0)
                return;

        /* Inform agent that we are done */
        kill(agent_pid, SIGTERM);
        kill(agent_pid, SIGCONT);
        wait_for_terminate(agent_pid, NULL);
        agent_pid = 0;
}
