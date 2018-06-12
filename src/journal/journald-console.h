/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2011 Lennart Poettering
***/

#include "journald-server.h"

void server_forward_console(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);
