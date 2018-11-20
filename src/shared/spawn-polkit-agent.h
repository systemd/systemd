/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/types.h>

#include "bus-util.h"
#include "static-destruct.h"

int polkit_agent_open(void);
void polkit_agent_close(void);

static inline int polkit_agent_open_if_enabled(
                BusTransport transport,
                bool ask_password) {

        /* Open the polkit agent as a child process if necessary */

        if (transport != BUS_TRANSPORT_LOCAL)
                return 0;

        if (!ask_password)
                return 0;

        return polkit_agent_open();
}

#if ENABLE_POLKIT
extern pid_t polkit_agent_pid;

void polkit_agent_closep(pid_t *p);

STATIC_DESTRUCTOR_REGISTER(polkit_agent_pid, polkit_agent_closep);
#endif
