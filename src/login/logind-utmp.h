/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

int manager_read_utmp(Manager *m);
void manager_connect_utmp(Manager *m);
void manager_reconnect_utmp(Manager *m);
