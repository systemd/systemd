/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-reset-failed.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_reset_failed(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        sd_bus *bus;
        int r, q;

        if (argc <= 1) /* Shortcut to trivial_method() if no argument is given */
                return verb_trivial_method(argc, argv, userdata);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = expand_unit_names(bus, strv_skip(argv, 1), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");

        STRV_FOREACH(name, names) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                q = bus_call_method(bus, bus_systemd_mgr, "ResetFailedUnit", &error, NULL, "s", *name);
                if (q < 0) {
                        log_error_errno(q, "Failed to reset failed state of unit %s: %s", *name, bus_error_message(&error, q));
                        if (r == 0)
                                r = q;
                }
        }

        return r;
}
