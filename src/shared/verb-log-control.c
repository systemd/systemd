/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "json-util.h"
#include "log.h"
#include "string-util.h"
#include "syslog-util.h"
#include "varlink-util.h"
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

int varlink_get_log_level(const char *address, int *ret_level, char **ret_level_str) {
        int r;

        assert(!isempty(address));

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to %s: %m", address);


        sd_json_variant *reply = NULL;
        r = varlink_call_and_log(
                        vl,
                        "io.systemd.service.GetLogLevel",
                        /* parameters= */ NULL,
                        &reply);
        if (r < 0)
                return r;

        struct {
                int level;
                const char *level_str;
        } info = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "level",       _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_log_level,       voffsetof(info, level),     SD_JSON_MANDATORY },
                { "levelString", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(info, level_str), SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG, &info);
        if (r < 0)
                return r;

        if (ret_level)
                *ret_level = info.level;

        if (ret_level_str)
                return strdup_to(ret_level_str, info.level_str);

        return 0;
}

int varlink_set_log_level(const char *address, const char *value) {
        int r;

        assert(!isempty(address));

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to %s: %m", address);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (value) {
                int level = log_level_from_string(value);
                if (level < 0)
                        return log_error_errno(level, "Failed to convert log level '%s': %m", value);

                r = sd_json_variant_new_integer(&v, level);
        } else
                r = sd_json_variant_new_null(&v);
        if (r < 0)
                return log_error_errno(r, "Failed to create JSON variant: %m");

        return varlink_callbo_and_log(
                        vl,
                        "io.systemd.service.SetLogLevel",
                        /* reply= */ NULL,
                        SD_JSON_BUILD_PAIR_VARIANT("level", v));
}
