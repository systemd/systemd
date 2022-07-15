/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "journald-server.h"

void server_forward_wall(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);
