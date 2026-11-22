/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-forward.h"

int machine_start_ssh_agent(Machine *machine);
void machine_stop_ssh_agent(Machine *machine);
