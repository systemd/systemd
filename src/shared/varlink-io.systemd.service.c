/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "macro.h"
#include "varlink-io.systemd.service.h"

static SD_VARLINK_DEFINE_METHOD(Ping);

static SD_VARLINK_DEFINE_METHOD(Reload);

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_DEFINE_INPUT(level, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_service,
                "io.systemd.service",
                &vl_method_Ping,
                &vl_method_Reload,
                &vl_method_SetLogLevel);

int varlink_method_ping(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        assert(link);

        if (sd_json_variant_elements(parameters) > 0)
                return sd_varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.service.Ping");

        return sd_varlink_reply(link, NULL);
}

int varlink_method_set_log_level(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "level", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64, 0, SD_JSON_MANDATORY },
                {}
        };

        int64_t level;
        uid_t uid;
        int r;

        assert(link);
        assert(parameters);

        /* NOTE: The method does have 1 parameter, but we must compare to 2 here, because
         * sd_json_variant_elements() breaks abstraction and exposes internal structure of JsonObject. */
        if (sd_json_variant_elements(parameters) != 2)
                return sd_varlink_error_invalid_parameter(link, parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
        if (r != 0)
                return r;

        if (LOG_PRI(level) != level)
                return sd_varlink_error_invalid_parameter(link, parameters);

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != getuid() && uid != 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);

        log_debug("Received io.systemd.service.SetLogLevel(%" PRIi64 ")", level);

        log_set_max_level(level);

        return sd_varlink_reply(link, NULL);
}
