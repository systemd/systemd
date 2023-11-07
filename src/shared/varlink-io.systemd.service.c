/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <unistd.h>

#include "varlink-io.systemd.service.h"

static VARLINK_DEFINE_METHOD(Ping);

static VARLINK_DEFINE_METHOD(Reload);

static VARLINK_DEFINE_METHOD(
                SetLogLevel,
                VARLINK_DEFINE_INPUT(level, VARLINK_INT, 0));

VARLINK_DEFINE_INTERFACE(
                io_systemd_service,
                "io.systemd.service",
                &vl_method_Ping,
                &vl_method_Reload,
                &vl_method_SetLogLevel);

int varlink_method_ping(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        assert(link);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.service.Ping");

        return varlink_reply(link, NULL);
}

int varlink_method_set_log_level(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "level", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int64, 0, JSON_MANDATORY },
                {}
        };

        int64_t level;
        uid_t uid;
        int r;

        assert(link);
        assert(parameters);

        /* NOTE: The method does have 1 parameter, but we must compare to 2 here, because
         * json_variant_elements() breaks abstraction and exposes internal structure of JsonObject. */
        if (json_variant_elements(parameters) != 2)
                return varlink_error_invalid_parameter(link, parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &level);
        if (r != 0)
                return r;

        if (LOG_PRI(level) != level)
                return varlink_error_invalid_parameter(link, parameters);

        r = varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != getuid() && uid != 0)
                return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, parameters);

        log_debug("Received io.systemd.service.SetLogLevel(%" PRIi64 ")", level);

        log_set_max_level(level);

        return varlink_reply(link, NULL);
}
