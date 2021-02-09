/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "pretty-print.h"
#include "syslog-util.h"
#include "systemctl-log-setting.h"
#include "systemctl-util.h"
#include "systemctl.h"

static void give_log_control1_hint(const char *name) {
        _cleanup_free_ char *link = NULL;

        if (arg_quiet)
                return;

        (void) terminal_urlify_man("org.freedesktop.LogControl1", "5", &link);

        log_notice("Hint: the service must declare BusName= and implement the appropriate D-Bus interface.\n"
                   "      See the %s for details.", link ?: "org.freedesktop.LogControl1(5) man page");
}

static int log_setting_internal(sd_bus *bus, const BusLocator* bloc, const char *verb, const char *value) {
        assert(bus);
        assert(STR_IN_SET(verb, "log-level", "log-target", "service-log-level", "service-log-target"));

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool level = endswith(verb, "log-level");
        int r;

        if (value) {
                if (level) {
                        r = log_level_from_string(value);
                        if (r < 0)
                                return log_error_errno(r, "\"%s\" is not a valid log level.", value);
                }

                r = bus_set_property(bus, bloc,
                                     level ? "LogLevel" : "LogTarget",
                                     &error, "s", value);
                if (r >= 0)
                        return 0;

                log_error_errno(r, "Failed to set log %s of %s to %s: %s",
                                level ? "level" : "target",
                                bloc->destination, value, bus_error_message(&error, r));
        } else {
                _cleanup_free_ char *t = NULL;

                r = bus_get_property_string(bus, bloc,
                                            level ? "LogLevel" : "LogTarget",
                                            &error, &t);
                if (r >= 0) {
                        puts(t);
                        return 0;
                }

                log_error_errno(r, "Failed to get log %s of %s: %s",
                                level ? "level" : "target",
                                bloc->destination, bus_error_message(&error, r));
        }

        if (sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_METHOD,
                                           SD_BUS_ERROR_UNKNOWN_OBJECT,
                                           SD_BUS_ERROR_UNKNOWN_INTERFACE,
                                           SD_BUS_ERROR_UNKNOWN_PROPERTY))
                give_log_control1_hint(bloc->destination);
        return r;
}

int log_setting(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r;

        assert(argc >= 1 && argc <= 2);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        return log_setting_internal(bus, bus_systemd_mgr, argv[0], argv[1]);
}

static int service_name_to_dbus(sd_bus *bus, const char *name, char **ret_dbus_name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *bus_name = NULL;
        int r;

        /* First, look for the BusName= property */
        _cleanup_free_ char *dbus_path = unit_dbus_path_from_name(name);
        if (!dbus_path)
                return log_oom();

        r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                dbus_path,
                                "org.freedesktop.systemd1.Service",
                                "BusName",
                                &error,
                                &bus_name);
        if (r < 0)
                return log_error_errno(r, "Failed to obtain BusName= property of %s: %s",
                                       name, bus_error_message(&error, r));

        if (isempty(bus_name)) {
                log_error("Unit %s doesn't declare BusName=.", name);
                give_log_control1_hint(name);
                return -ENOLINK;
        }

        *ret_dbus_name = TAKE_PTR(bus_name);
        return 0;
}

int service_log_setting(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        _cleanup_free_ char *unit = NULL, *dbus_name = NULL;
        int r;

        assert(argc >= 2 && argc <= 3);

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = unit_name_mangle_with_suffix(argv[1], argv[0],
                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                         ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        r = service_name_to_dbus(bus, unit, &dbus_name);
        if (r < 0)
                return r;

        const BusLocator bloc = {
                .destination = dbus_name,
                .path = "/org/freedesktop/LogControl1",
                .interface = "org.freedesktop.LogControl1",
        };

        return log_setting_internal(bus, &bloc, argv[0], argv[2]);
}
