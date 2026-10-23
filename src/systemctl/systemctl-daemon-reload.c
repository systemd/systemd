/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "constants.h"
#include "string-util.h"
#include "systemctl.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-util.h"

int daemon_reload(enum action action, bool graceful) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *method;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        switch (action) {

        case ACTION_RELOAD:
                method = "Reload";
                break;

        case ACTION_REEXEC:
                method = "Reexecute";
                break;

        default:
                return -EINVAL;
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
        if (r < 0)
                return bus_log_create_error(r);

        /* Reloading the daemon may take long, hence set a longer timeout here */
        r = sd_bus_call(bus, m, DAEMON_RELOAD_TIMEOUT_SEC, &error, NULL);

        /* On reexecution, we expect a disconnect, not a reply */
        if (IN_SET(r, -ETIMEDOUT, -ECONNRESET) && action == ACTION_REEXEC)
                return 1;
        if (r < 0) {
                if (graceful) { /* If graceful mode is selected, debug log, but don't fail */
                        log_debug_errno(r, "%s daemon failed via the bus, ignoring: %s",
                                        method, bus_error_message(&error, r));
                        return 0;
                }

                return log_error_errno(r, "%s daemon failed: %s",
                                       method, bus_error_message(&error, r));
        }

        return 1;
}

int daemon_reload_after_vendor_install(void) {
        /* We wrote below /usr/ on a system whose manager is running, so it has not seen any of this yet.
         * Every other reason to end up on the client side leaves no manager to tell. Graceful: the files are
         * already in place, and failing to reach the manager must not turn that into an error. */

        if (install_client_side() != INSTALL_CLIENT_SIDE_VENDOR || arg_no_reload)
                return 0;

        return daemon_reload(ACTION_RELOAD, /* graceful= */ true);
}

int verb_daemon_reload(int argc, char *argv[], uintptr_t _data, void *userdata) {
        enum action a;
        int r;

        assert(argc >= 1);

        if (streq(argv[0], "daemon-reexec"))
                a = ACTION_REEXEC;
        else if (streq(argv[0], "daemon-reload"))
                a = ACTION_RELOAD;
        else
                assert_not_reached();

        r = daemon_reload(a, /* graceful= */ false);
        if (r < 0)
                return r;

        return 0;
}
