/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "pretty-print.h"
#include "syslog-util.h"
#include "systemctl-log-setting.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "verb-log-control.h"

static void give_log_control1_hint(const char *name) {
        _cleanup_free_ char *link = NULL;

        if (arg_quiet)
                return;

        (void) terminal_urlify_man("org.freedesktop.LogControl1", "5", &link);

        log_notice("Hint: the service must declare BusName= and implement the appropriate D-Bus interface.\n"
                   "      See the %s for details.", link ?: "org.freedesktop.LogControl1(5) man page");
}

int verb_log_setting(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r;

        assert(argc >= 1 && argc <= 2);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        return verb_log_control_common(bus, "org.freedesktop.systemd1", argv[0], argv[1]);
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

int verb_service_log_setting(int argc, char *argv[], void *userdata) {
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

        r = verb_log_control_common(bus, dbus_name, argv[0], argv[2]);

        if (r == -EBADR)
                give_log_control1_hint(dbus_name);

        return r;
}
