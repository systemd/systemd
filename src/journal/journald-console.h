/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct Server Server;

void server_forward_console(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);
