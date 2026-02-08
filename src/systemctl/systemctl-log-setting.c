/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-varlink.h"
#include "sd-varlink-idl.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "log.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "systemctl.h"
#include "systemctl-log-setting.h"
#include "systemctl-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "varlink-util.h"
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

        if (isempty(bus_name))
                return 0; /* No D-Bus name configured */

        *ret_dbus_name = TAKE_PTR(bus_name);
        return 1; /* Found D-Bus name */
}

static int get_varlink_socket_path_from_socket_unit(sd_bus *bus, const char *socket_unit, char **ret_path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *fdname = NULL;
        const char *type, *path;
        int r;

        assert(bus);
        assert(socket_unit);
        assert(ret_path);

        _cleanup_free_ char *dbus_path = unit_dbus_path_from_name(socket_unit);
        if (!dbus_path)
                return log_oom();

        /* Check if this socket has FileDescriptorName=varlink */
        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Socket",
                        "FileDescriptorName",
                        &error,
                        &fdname);
        if (r < 0)
                return log_error_errno(r, "Failed to get FileDescriptorName property of %s: %s",
                                       socket_unit, bus_error_message(&error, r));

        if (!streq(fdname, "varlink")) {
                *ret_path = NULL;
                return 0; /* Not a varlink socket */
        }

        /* Get the Listen property to find the socket path */
        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Socket",
                        "Listen",
                        &error,
                        &reply,
                        "a(ss)");
        if (r < 0)
                return log_error_errno(r, "Failed to get Listen property of %s: %s",
                                       socket_unit, bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ss)", &type, &path)) > 0)
                /* We're looking for stream sockets (ListenStream=) */
                if (streq(type, "Stream")) {
                        char *p = strdup(path);
                        if (!p)
                                return log_oom();

                        *ret_path = p;
                        return 1; /* Found varlink socket path */
                }
        if (r < 0)
                return bus_log_parse_error(r);

        *ret_path = NULL;
        return 0; /* No suitable socket found */
}

static int service_name_to_varlink_socket(sd_bus *bus, const char *name, char **ret_socket_path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **triggered_by = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(ret_socket_path);

        _cleanup_free_ char *dbus_path = unit_dbus_path_from_name(name);
        if (!dbus_path)
                return log_oom();

        /* Get the TriggeredBy property to find associated socket units */
        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Unit",
                        "TriggeredBy",
                        &error,
                        &triggered_by);
        if (r < 0)
                return log_error_errno(r, "Failed to get TriggeredBy property of %s: %s",
                                       name, bus_error_message(&error, r));

        /* Check each triggering socket unit for varlink sockets */
        STRV_FOREACH(socket_unit, triggered_by) {
                if (!endswith(*socket_unit, ".socket"))
                        continue;

                r = get_varlink_socket_path_from_socket_unit(bus, *socket_unit, ret_socket_path);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1; /* Found a varlink socket */
        }

        return 0; /* No varlink socket found */
}

static int varlink_call_get_log_level(const char *socket_path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        const char *error_id = NULL, *level = NULL;
        sd_json_variant *reply = NULL;
        int r;

        assert(socket_path);

        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink socket %s: %m", socket_path);

        r = sd_varlink_call(vl, "org.freedesktop.LogControl.GetLogLevel", /* parameters= */ NULL, &reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to call org.freedesktop.LogControl.GetLogLevel on %s: %m", socket_path);
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "org.freedesktop.LogControl.GetLogLevel on %s returned an error: %s",
                                       socket_path,
                                       error_id);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "level", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &level);
        if (r < 0)
                return r;

        puts(level);
        return 0;
}

static int varlink_call_set_log_level(const char *socket_path, const char *level) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(socket_path);
        assert(level);

        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink socket %s: %m", socket_path);

        return varlink_callbo_and_log(vl, "org.freedesktop.LogControl.SetLogLevel", /* reply= */ NULL,
                                      SD_JSON_BUILD_PAIR_STRING("level", level));
}

static int varlink_has_log_control_interface(const char *socket_path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_strv_free_ char **interfaces = NULL;
        sd_json_variant *info_reply = NULL;
        const char *error_id = NULL;
        int r;

        assert(socket_path);

        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink socket %s: %m", socket_path);

        /* Call org.varlink.service.GetInfo to get the list of interfaces */
        r = sd_varlink_call(vl, "org.varlink.service.GetInfo", /* parameters= */ NULL, &info_reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to call org.varlink.service.GetInfo on %s: %m", socket_path);
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, info_reply),
                                       "org.varlink.service.GetInfo on %s returned an error: %s",
                                       socket_path,
                                       error_id);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "interfaces", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(info_reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &interfaces);
        if (r < 0)
                return r;

        /* Check if org.freedesktop.LogControl interface is available */
        return strv_contains(interfaces, "org.freedesktop.LogControl");
}

static int verb_service_log_setting_varlink(const char *socket_path, const char *verb, const char *value) {
        int r;

        assert(socket_path);
        assert(verb);

        r = varlink_has_log_control_interface(socket_path);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Service does not implement org.freedesktop.LogControl interface.");

        if (value) {
                /* Validate log level before sending */
                if (log_level_from_string(value) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "\"%s\" is not a valid log level.", value);

                return varlink_call_set_log_level(socket_path, value);
        }

        return varlink_call_get_log_level(socket_path);
}

int verb_service_log_setting(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *unit = NULL, *dbus_name = NULL, *varlink_socket_path = NULL;
        sd_bus *bus;
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

        /* First try D-Bus */
        r = service_name_to_dbus(bus, unit, &dbus_name);
        if (r < 0)
                return r;
        if (r > 0) {
                /* Service has a D-Bus name, use D-Bus LogControl1 interface */
                r = verb_log_control_common(bus, dbus_name, argv[0], argv[2]);
                if (r == -EBADR)
                        give_log_control1_hint(dbus_name);
                return r;
        }

        /* No D-Bus name, try Varlink */
        r = service_name_to_varlink_socket(bus, unit, &varlink_socket_path);
        if (r < 0)
                return r;
        if (r > 0)
                /* Found a varlink socket, use Varlink io.systemd.service interface */
                return verb_service_log_setting_varlink(varlink_socket_path, argv[0], argv[2]);

        /* Neither D-Bus nor Varlink available */
        log_error("Unit %s doesn't declare BusName= and has no Varlink socket.", unit);
        give_log_control1_hint(unit);
        return -ENOLINK;
}
