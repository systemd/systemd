/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "ask-password-agent.h"
#include "exec-util.h"
#include "log.h"
#include "process-util.h"

static pid_t agent_pid = 0;

int ask_password_agent_open(void) {
        int r;

        if (agent_pid > 0)
                return 0;

        r = shall_fork_agent();
        if (r <= 0)
                return r;

        r = fork_agent("(sd-askpwagent)",
                       NULL, 0,
                       &agent_pid,
                       SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH,
                       "--watch");
        if (r < 0)
                return log_error_errno(r, "Failed to fork TTY ask password agent: %m");

        return 1;
}

void ask_password_agent_close(void) {

        if (agent_pid <= 0)
                return;

        /* Inform agent that we are done */
        sigterm_wait(TAKE_PID(agent_pid));
}

int ask_password_agent_open_if_enabled(BusTransport transport, bool ask_password) {

        /* Open the ask password agent as a child process if necessary */

        if (transport != BUS_TRANSPORT_LOCAL)
                return 0;

        if (!ask_password)
                return 0;

        return ask_password_agent_open();
}
