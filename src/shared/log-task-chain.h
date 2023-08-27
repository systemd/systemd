/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <sys/types.h>

#include "sd-bus.h"

void log_task_chain_msg(sd_bus_message *message, const char *special_action_string);
void log_task_chain_pid(pid_t pid, const char *special_action_string);
