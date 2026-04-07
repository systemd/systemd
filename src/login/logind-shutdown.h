/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

#define SHUTDOWN_SCHEDULE_FILE "/run/systemd/shutdown/scheduled"

int manager_have_multiple_sessions(Manager *m, uid_t uid);

void log_shutdown_caller(const PidRef *caller, const char *method);

/* manager_verify_shutdown_creds() takes *either* a "message" or "link" depending on if it is used
 * to validate a D-Bus or Varlink shutdown request. When varlink is used the sd_bus_error *error
 * must be NULL */
int manager_verify_shutdown_creds(Manager *m, sd_bus_message *message, sd_varlink *link, const HandleActionData *a, uint64_t flags, sd_bus_error *error);

void manager_reset_scheduled_shutdown(Manager *m);
