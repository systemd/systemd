/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "env-util.h"
#include "json-util.h"
#include "strv.h"
#include "varlink-io.systemd.service.h"

static SD_VARLINK_DEFINE_METHOD(Ping);

static SD_VARLINK_DEFINE_METHOD(Reload);

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The maximum log level, using BSD syslog log level integers."),
                SD_VARLINK_DEFINE_INPUT(level, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetEnvironment,
                SD_VARLINK_FIELD_COMMENT("Returns the current environment block, i.e. the contents of environ[]."),
                SD_VARLINK_DEFINE_OUTPUT(environment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(
                InconsistentEnvironment);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_service,
                "io.systemd.service",
                SD_VARLINK_INTERFACE_COMMENT("An interface to control basic properties of systemd services."),
                SD_VARLINK_SYMBOL_COMMENT("Checks if the service is running."),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Reloads configuration files."),
                &vl_method_Reload,
                SD_VARLINK_SYMBOL_COMMENT("Sets the maximum log level."),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Get current environment block."),
                &vl_method_GetEnvironment,
                SD_VARLINK_SYMBOL_COMMENT("Returned if the environment block is currently not in a valid state."),
                &vl_error_InconsistentEnvironment);

/* Generic implementations for some of the method calls above */

int varlink_method_ping(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.service.Ping");

        return sd_varlink_reply(link, NULL);
}

int varlink_method_set_log_level(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "level", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_log_level, 0, SD_JSON_MANDATORY },
                {}
        };

        int r, level;
        uid_t uid;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
        if (r != 0)
                return r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != getuid())
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);

        log_debug("Received io.systemd.service.SetLogLevel(%i)", level);

        log_set_max_level(level);

        return sd_varlink_reply(link, NULL);
}

int varlink_method_get_environment(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        uid_t uid;
        int r;

        assert(link);
        assert(parameters);

        /* This is a lot like /proc/$PID/environ, but can properly report the actual environment block as
         * seen from the process itself, which might be quite different from the contents of the memory that
         * was originally passed in. This is particularly relevant for cases where the environ[] block has
         * been enlarged and similar. */

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        /* Don't hand out environment block to arbitrary clients, in some cases people might make the mistake
         * of passing secrets via env vars */
        if (uid != 0 && uid != getuid())
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);

        log_debug("Received io.systemd.service.GetEnvironment()");

        _cleanup_strv_free_ char **l = NULL;
        STRV_FOREACH(e, environ) {
                if (!env_assignment_is_valid(*e))
                        goto invalid;
                if (!utf8_is_valid(*e))
                        goto invalid;

                r = strv_env_replace_strdup(&l, *e);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRV("environment", l));

invalid:
        return sd_varlink_error(link, "io.systemd.service.InconsistentEnvironment", parameters);
}
