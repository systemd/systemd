/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-error.h"
#include "log.h"
#include "strv.h"
#include "syslog-util.h"
#include "verb-log-control.h"

int verb_log_control_common(sd_bus *bus, const char *destination, const char *verb, const char *value) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool level = endswith(verb, "log-level");
        const BusLocator bloc = {
                .destination = destination,
                .path = "/org/freedesktop/LogControl1",
                .interface = "org.freedesktop.LogControl1",
        };
        int r;

        assert(bus);
        assert(endswith(verb, "log-level") || endswith(verb, "log-target"));

        if (value) {
                if (level) {
                        r = log_level_from_string(value);
                        if (r < 0)
                                return log_error_errno(r, "\"%s\" is not a valid log level.", value);
                }

                r = bus_set_property(bus, &bloc,
                                     level ? "LogLevel" : "LogTarget",
                                     &error, "s", value);
                if (r < 0)
                        return log_error_errno(r, "Failed to set log %s of %s to %s: %s",
                                               level ? "level" : "target",
                                               bloc.destination, value, bus_error_message(&error, r));
        } else {
                _cleanup_free_ char *t = NULL;

                r = bus_get_property_string(bus, &bloc,
                                            level ? "LogLevel" : "LogTarget",
                                            &error, &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to get log %s of %s: %s",
                                               level ? "level" : "target",
                                               bloc.destination, bus_error_message(&error, r));
                puts(t);
        }

        return 0;
}
