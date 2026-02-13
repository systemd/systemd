/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int manager_setup_varlink_server(Manager *m);
int manager_setup_varlink_metrics_server(Manager *m);

int manager_varlink_init(Manager *m);
void manager_varlink_done(Manager *m);

/* The manager is expected to send an update to systemd-oomd if one of the following occurs:
 * - The value of ManagedOOM*= properties change
 * - A unit with ManagedOOM*= properties changes unit active state */
int manager_varlink_send_managed_oom_update(Unit *u);

void manager_varlink_send_pending_reload_message(Manager *m);
