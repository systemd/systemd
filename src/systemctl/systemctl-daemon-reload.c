/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-util.h"
#include "systemctl.h"

int daemon_reload(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *method;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        switch (arg_action) {

        case ACTION_RELOAD:
                method = "Reload";
                break;

        case ACTION_REEXEC:
                method = "Reexecute";
                break;

        case ACTION_SYSTEMCTL:
                method = streq(argv[0], "daemon-reexec") ? "Reexecute" :
                                     /* "daemon-reload" */ "Reload";
                break;

        default:
                assert_not_reached("Unexpected action");
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
        if (r < 0)
                return bus_log_create_error(r);

        /* Note we use an extra-long timeout here. This is because a reload or reexec means generators are
         * rerun which are timed out after DEFAULT_TIMEOUT_USEC. Let's use twice that time here, so that the
         * generators can have their timeout, and for everything else there's the same time budget in
         * place. */

        r = sd_bus_call(bus, m, DEFAULT_TIMEOUT_USEC * 2, &error, NULL);

        /* On reexecution, we expect a disconnect, not a reply */
        if (IN_SET(r, -ETIMEDOUT, -ECONNRESET) && streq(method, "Reexecute"))
                r = 0;

        if (r < 0 && arg_action == ACTION_SYSTEMCTL)
                return log_error_errno(r, "Failed to reload daemon: %s", bus_error_message(&error, r));

        /* Note that for the legacy commands (i.e. those with action != ACTION_SYSTEMCTL) we support
         * fallbacks to the old ways of doing things, hence don't log any error in that case here. */

        return r < 0 ? r : 0;
}
