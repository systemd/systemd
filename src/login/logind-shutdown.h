/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"
#include "pidref.h"

#define SHUTDOWN_SCHEDULE_FILE "/run/systemd/shutdown/scheduled"

int have_multiple_sessions(Manager *m, uid_t uid);

void manager_log_shutdown_caller(const PidRef *caller, const char *method);

/* verify_shutdown_creds() takes *either* a "message" or "link" depending on if it is used
 * to validate a D-Bus or Varlink shutdown request. When varlink is used the sd_bus_error *error
 * must be NULL */
int verify_shutdown_creds(Manager *m, sd_bus_message *message, sd_varlink *link, const HandleActionData *a, uint64_t flags, sd_bus_error *error);

void reset_scheduled_shutdown(Manager *m);
