/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-util.h"
#include "log.h"
#include "sd-bus.h"
#include "syslog-util.h"

int bus_property_get_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *t = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "s", t);
}

int bus_property_set_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        r = log_level_from_string(t);
        if (r < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log level '%s'", t);

        log_info("Setting log level to %s.", t);
        log_set_max_level(r);

        return 0;
}

BUS_DEFINE_PROPERTY_GET_GLOBAL(bus_property_get_log_target, "s", log_target_to_string(log_get_target()));

int bus_property_set_log_target(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        LogTarget target;
        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        target = log_target_from_string(t);
        if (target < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log target '%s'", t);

        log_info("Setting log target to %s.", log_target_to_string(target));
        log_set_target(target);
        log_open();

        return 0;
}

BUS_DEFINE_PROPERTY_GET_GLOBAL(bus_property_get_syslog_identifier, "s", program_invocation_short_name);

static const sd_bus_vtable log_control_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", bus_property_get_log_level, bus_property_set_log_level, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", bus_property_get_log_target, bus_property_set_log_target, 0, 0),
        SD_BUS_PROPERTY("SyslogIdentifier", "s", bus_property_get_syslog_identifier, 0, 0),

        /* One of those days we might want to add a similar, second interface to cover common service
         * operations such as Reload(), Reexecute(), Exit() …  and maybe some properties exposing version
         * number and other meta-data of the service. */

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation log_control_object = {
        "/org/freedesktop/LogControl1",
        "org.freedesktop.LogControl1",
        .vtables = BUS_VTABLES(log_control_vtable),
};
