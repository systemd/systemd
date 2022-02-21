/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "parse-util.h"
#include "systemctl-service-watchdogs.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_service_watchdogs(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int b, r;

        assert(argv);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        if (argc == 1) {
                /* get ServiceWatchdogs */
                r = bus_get_property_trivial(bus, bus_systemd_mgr, "ServiceWatchdogs", &error, 'b', &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to get service-watchdog state: %s", bus_error_message(&error, r));

                printf("%s\n", yes_no(!!b));

        } else {
                /* set ServiceWatchdogs */
                assert(argc == 2);

                b = parse_boolean(argv[1]);
                if (b < 0)
                        return log_error_errno(b, "Failed to parse service-watchdogs argument: %m");

                r = bus_set_property(bus, bus_systemd_mgr, "ServiceWatchdogs", &error, "b", b);
                if (r < 0)
                        return log_error_errno(r, "Failed to set service-watchdog state: %s", bus_error_message(&error, r));
        }

        return 0;
}
