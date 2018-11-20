/* SPDX-License-Identifier: LGPL-2.1+ */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "process-util.h"
#include "spawn-ask-password-agent.h"
#include "util.h"

pid_t ask_password_agent_pid = 0;

int ask_password_agent_open(void) {
        int r;

        if (ask_password_agent_pid > 0)
                return 0;

        /* We check STDIN here, not STDOUT, since this is about input,
         * not output */
        if (!isatty(STDIN_FILENO))
                return 0;

        if (!is_main_thread())
                return -EPERM;

        r = fork_agent("(sd-askpwagent)",
                       NULL, 0,
                       &ask_password_agent_pid,
                       SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH,
                       SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH, "--watch", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fork TTY ask password agent: %m");

        return 1;
}

void ask_password_agent_closep(pid_t *p) {
        assert(p);

        if (*p <= 0)
                return;

        /* Inform agent that we are done */
        (void) kill_and_sigcont(*p, SIGTERM);
        (void) wait_for_terminate(*p, NULL);
        *p = 0;
}

void ask_password_agent_close(void) {
        ask_password_agent_closep(&ask_password_agent_pid);
}
