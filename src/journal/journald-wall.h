/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

typedef struct Manager Manager;

void manager_forward_wall(Manager *m, int priority, const char *identifier, const char *message, const struct ucred *ucred);
