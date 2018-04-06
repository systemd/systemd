/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

#include "bus-util.h"

int polkit_agent_open(void);
void polkit_agent_close(void);

static inline void polkit_agent_open_if_enabled(
                BusTransport transport,
                bool ask_password) {

        /* Open the polkit agent as a child process if necessary */

        if (transport != BUS_TRANSPORT_LOCAL)
                return;

        if (!ask_password)
                return;

        polkit_agent_open();
}
