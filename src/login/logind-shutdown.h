/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

#define SHUTDOWN_SCHEDULE_FILE "/run/systemd/shutdown/scheduled"

void manager_reset_scheduled_shutdown(Manager *m);
