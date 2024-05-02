/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "login-util.h"

#include "sysupdate-util.h"

int reboot_now(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open bus connection: %m");

        r = bus_call_method(bus, bus_login_mgr, "RebootWithFlags", &error, NULL, "t",
                            (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS);
        if (r < 0)
                return log_error_errno(r, "Failed to issue reboot request: %s", bus_error_message(&error, r));

        return 0;
}
