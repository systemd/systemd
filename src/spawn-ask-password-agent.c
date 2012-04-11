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

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>

#include "log.h"
#include "util.h"
#include "spawn-ask-password-agent.h"

static pid_t agent_pid = 0;

int ask_password_agent_open(void) {
        int r;

        if (agent_pid > 0)
                return 0;

        /* We check STDIN here, not STDOUT, since this is about input,
         * not output */
        if (!isatty(STDIN_FILENO))
                return 0;

        r = fork_agent(&agent_pid,
                       NULL, 0,
                       SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH,
                       SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH, "--watch", NULL);
        if (r < 0)
                log_error("Failed to fork TTY ask password agent: %s", strerror(-r));

        return r;
}

void ask_password_agent_close(void) {

        if (agent_pid <= 0)
                return;

        /* Inform agent that we are done */
        kill(agent_pid, SIGTERM);
        kill(agent_pid, SIGCONT);
        wait_for_terminate(agent_pid, NULL);
        agent_pid = 0;
}
