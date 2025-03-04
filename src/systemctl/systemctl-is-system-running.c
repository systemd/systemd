/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-daemon.h"

#include "systemctl-util.h"
#include "systemctl-is-system-running.h"
#include "virt.h"
#include "systemctl.h"
#include "bus-util.h"
#include "bus-locator.h"
#include "bus-error.h"

static int match_startup_finished(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        char **state = ASSERT_PTR(userdata);
        int r;

        r = bus_get_property_string(sd_bus_message_get_bus(m), bus_systemd_mgr, "SystemState", NULL, state);

        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), r);
        return 0;
}

int verb_is_system_running(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot_startup_finished = NULL;
        _cleanup_(sd_event_unrefp) sd_event* event = NULL;
        _cleanup_free_ char *state = NULL;
        sd_bus *bus;
        int r;

        if (!isempty(arg_root) || running_in_chroot() > 0 || (arg_transport == BUS_TRANSPORT_LOCAL && !sd_booted())) {
                if (!arg_quiet)
                        puts("offline");
                return EXIT_FAILURE;
        }

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        if (arg_wait) {
                r = sd_event_default(&event);
                if (r >= 0)
                        r = sd_bus_attach_event(bus, event, 0);
                if (r >= 0)
                        r = bus_match_signal_async(
                                        bus,
                                        &slot_startup_finished,
                                        bus_systemd_mgr,
                                        "StartupFinished",
                                        match_startup_finished, NULL, &state);
                if (r < 0) {
                        log_warning_errno(r, "Failed to request match for StartupFinished: %m");
                        arg_wait = false;
                }
        }

        r = bus_get_property_string(bus, bus_systemd_mgr, "SystemState", &error, &state);
        if (r < 0) {
                log_warning_errno(r, "Failed to query system state: %s", bus_error_message(&error, r));

                if (!arg_quiet)
                        puts("unknown");
                return EXIT_FAILURE;
        }

        if (arg_wait && STR_IN_SET(state, "initializing", "starting")) {
                /* The signal handler will allocate memory and assign to 'state', hence need to free previous
                 * one before entering the event loop. */
                state = mfree(state);

                r = sd_event_loop(event);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get property from event loop: %m");
                        if (!arg_quiet)
                                puts("unknown");
                        return EXIT_FAILURE;
                }

                assert(state);
        }

        if (!arg_quiet)
                puts(state);

        return streq(state, "running") ? EXIT_SUCCESS : EXIT_FAILURE;
}
