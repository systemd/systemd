/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-wait-for-units.h"
#include "systemctl-clean-or-freeze.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_clean_or_freeze(int argc, char *argv[], void *userdata) {
        _cleanup_(bus_wait_for_units_freep) BusWaitForUnits *w = NULL;
        _cleanup_strv_free_ char **names = NULL;
        int r, ret = EXIT_SUCCESS;
        const char *method;
        sd_bus *bus;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        if (!arg_clean_what) {
                arg_clean_what = strv_new("cache", "runtime");
                if (!arg_clean_what)
                        return log_oom();
        }

        r = expand_unit_names(bus, strv_skip(argv, 1), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");

        if (!arg_no_block) {
                r = bus_wait_for_units_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate unit waiter: %m");
        }

        if (streq(argv[0], "clean"))
                method = "CleanUnit";
        else if (streq(argv[0], "freeze"))
                method = "FreezeUnit";
        else if (streq(argv[0], "thaw"))
                method = "ThawUnit";
        else
                assert_not_reached();

        STRV_FOREACH(name, names) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                if (w) {
                        /* If we shall wait for the cleaning to complete, let's add a ref on the unit first */
                        r = bus_call_method(bus, bus_systemd_mgr, "RefUnit", &error, NULL, "s", *name);
                        if (r < 0) {
                                log_error_errno(r, "Failed to add reference to unit %s: %s", *name, bus_error_message(&error, r));
                                if (ret == EXIT_SUCCESS)
                                        ret = r;
                                continue;
                        }
                }

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *name);
                if (r < 0)
                        return bus_log_create_error(r);

                if (streq(method, "CleanUnit")) {
                        r = sd_bus_message_append_strv(m, arg_clean_what);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_call(bus, m, 0, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to %s unit %s: %s", argv[0], *name, bus_error_message(&error, r));
                        if (ret == EXIT_SUCCESS) {
                                ret = r;
                                continue;
                        }
                }

                if (w) {
                        r = bus_wait_for_units_add_unit(w, *name, BUS_WAIT_REFFED|BUS_WAIT_FOR_MAINTENANCE_END, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to watch unit %s: %m", *name);
                }
        }

        r = bus_wait_for_units_run(w);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for units: %m");
        if (r == BUS_WAIT_FAILURE)
                ret = EXIT_FAILURE;

        return ret;
}
