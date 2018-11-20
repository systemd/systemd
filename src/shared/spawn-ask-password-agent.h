/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/types.h>

#include "static-destruct.h"

extern pid_t ask_password_agent_pid;

int ask_password_agent_open(void);
void ask_password_agent_close(void);
void ask_password_agent_closep(pid_t *p);

STATIC_DESTRUCTOR_REGISTER(ask_password_agent_pid, ask_password_agent_closep);
