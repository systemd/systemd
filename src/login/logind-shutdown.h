/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

#define SHUTDOWN_SCHEDULE_FILE "/run/systemd/shutdown/scheduled"

int have_multiple_sessions(Manager *m, uid_t uid);
int verify_shutdown_creds(Manager *m, sd_bus_message *message, const HandleActionData *a, uint64_t flags, sd_bus_error *error);
void reset_scheduled_shutdown(Manager *m);
