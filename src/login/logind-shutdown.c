/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "fs-util.h"
#include "logind.h"
#include "logind-dbus.h"
#include "logind-shutdown.h"

void manager_reset_scheduled_shutdown(Manager *m) {
        assert(m);

        m->scheduled_shutdown_timeout_source = sd_event_source_disable_unref(m->scheduled_shutdown_timeout_source);
        m->wall_message_timeout_source = sd_event_source_disable_unref(m->wall_message_timeout_source);
        m->nologin_timeout_source = sd_event_source_disable_unref(m->nologin_timeout_source);

        m->scheduled_shutdown_action = _HANDLE_ACTION_INVALID;
        m->scheduled_shutdown_timeout = USEC_INFINITY;
        m->scheduled_shutdown_uid = UID_INVALID;
        m->scheduled_shutdown_tty = mfree(m->scheduled_shutdown_tty);
        m->shutdown_dry_run = false;

        if (m->unlink_nologin) {
                (void) unlink_or_warn("/run/nologin");
                m->unlink_nologin = false;
        }

        (void) unlink(SHUTDOWN_SCHEDULE_FILE);

        manager_send_changed(m, "ScheduledShutdown");
}
