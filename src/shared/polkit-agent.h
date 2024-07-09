/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "bus-util.h"

int polkit_agent_open(void);
void polkit_agent_close(void);

int polkit_agent_open_if_enabled(BusTransport transport, bool ask_password);
