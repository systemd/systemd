/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-forward.h"

int manager_ssh_agent_init(Manager *m);
void manager_ssh_agent_done(Manager *m);
