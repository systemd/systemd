/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

void manager_forward_console(Manager *m, int priority, const char *identifier, const char *message, const struct ucred *ucred);
