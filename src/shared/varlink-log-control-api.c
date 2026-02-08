/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "log.h"
#include "syslog-util.h"
#include "varlink-log-control-api.h"
#include "varlink-org.freedesktop.LogControl.h"

int varlink_log_control_api_register(sd_varlink_server *s) {
        int r;

        assert(s);

        r = sd_varlink_server_add_interface(s, &vl_interface_org_freedesktop_LogControl);
        if (r < 0)
                return r;

        return sd_varlink_server_bind_method_many(
                        s,
                        "org.freedesktop.LogControl.GetLogLevel",         varlink_method_get_log_level,
                        "org.freedesktop.LogControl.SetLogLevel",         varlink_method_set_log_level_string,
                        "org.freedesktop.LogControl.GetLogTarget",        varlink_method_get_log_target,
                        "org.freedesktop.LogControl.SetLogTarget",        varlink_method_set_log_target,
                        "org.freedesktop.LogControl.GetSyslogIdentifier", varlink_method_get_syslog_identifier);
}

int varlink_method_get_log_level(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("level", t));
}

int varlink_method_set_log_level_string(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "level", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        const char *level_string = NULL;
        int r, level;
        uid_t uid;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &level_string);
        if (r != 0)
                return r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != getuid())
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);

        level = log_level_from_string(level_string);
        if (level < 0)
                return sd_varlink_error_invalid_parameter_name(link, "level");

        log_info("Setting log level to %s.", level_string);
        log_set_max_level(level);

        return sd_varlink_reply(link, NULL);
}

int varlink_method_get_log_target(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("target", log_target_to_string(log_get_target())));
}

int varlink_method_set_log_target(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "target", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        const char *target_string = NULL;
        LogTarget target;
        int r;
        uid_t uid;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &target_string);
        if (r != 0)
                return r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != getuid())
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);

        target = log_target_from_string(target_string);
        if (target < 0)
                return sd_varlink_error_invalid_parameter_name(link, "target");

        log_info("Setting log target to %s.", log_target_to_string(target));
        log_set_target_and_open(target);

        return sd_varlink_reply(link, NULL);
}

int varlink_method_get_syslog_identifier(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("identifier", program_invocation_short_name));
}
