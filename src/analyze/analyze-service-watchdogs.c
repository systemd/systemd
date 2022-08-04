/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-service-watchdogs.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "parse-util.h"

int verb_service_watchdogs(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int b, r;

        assert(IN_SET(argc, 1, 2));
        assert(argv);

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        if (argc == 1) {
                /* get ServiceWatchdogs */
                r = bus_get_property_trivial(bus, bus_systemd_mgr, "ServiceWatchdogs", &error, 'b', &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to get service-watchdog state: %s", bus_error_message(&error, r));

                printf("%s\n", yes_no(!!b));

        } else {
                /* set ServiceWatchdogs */
                b = parse_boolean(argv[1]);
                if (b < 0)
                        return log_error_errno(b, "Failed to parse service-watchdogs argument: %m");

                r = bus_set_property(bus, bus_systemd_mgr, "ServiceWatchdogs", &error, "b", b);
                if (r < 0)
                        return log_error_errno(r, "Failed to set service-watchdog state: %s", bus_error_message(&error, r));
        }

        return EXIT_SUCCESS;
}
