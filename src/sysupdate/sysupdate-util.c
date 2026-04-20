/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-varlink.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "json-util.h"
#include "log.h"
#include "login-util.h"
#include "sysupdate-util.h"
#include "varlink-util.h"

int reboot_now(void) {
        int r;

        /* Always honor inhibitors when root triggers the reboot: sysupdate doesn't expose an
         * override, and an interactive root user running the update is expected to respect
         * the usual inhibitor set. */

        /* Try Varlink first */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Login");
        if (r >= 0) {
                r = varlink_callbo_and_log(
                                vl, "io.systemd.Login.Reboot", NULL,
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS));
                if (r >= 0)
                        return 0;
                log_debug_errno(r, "Failed to reboot via Varlink, falling back to D-Bus: %m");
        }

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open bus connection: %m");

        r = bus_call_method(bus, bus_login_mgr, "RebootWithFlags", &error, NULL, "t",
                            (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS);
        if (r < 0)
                return log_error_errno(r, "Failed to issue reboot request: %s", bus_error_message(&error, r));

        return 0;
}
