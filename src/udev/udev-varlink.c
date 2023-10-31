/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "strv.h"
#include "udev-manager.h"
#include "udev-varlink.h"
#include "varlink-io.systemd.service.h"

static int vl_method_reload(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(link);
        assert(parameters);

        if (sd_json_variant_elements(parameters) > 0)
                return sd_varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.service.Reload()");

        manager_reload(m, /* force = */ true);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_log_level(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                {"level", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, 0, SD_JSON_MANDATORY},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        int64_t level;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
        if (r < 0)
                return r;

        if (LOG_PRI(level) != level)
                return sd_varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.system.SetLogLevel(%" PRIi64 ")", level);

        manager_set_log_level(m, level);

        return sd_varlink_reply(link, NULL);
}

static int update_exec_queue(sd_varlink *link, sd_json_variant *parameters, void *userdata, bool stop) {
        Manager *m = ASSERT_PTR(userdata);

        assert(link);

        if (sd_json_variant_elements(parameters) > 0)
                return sd_varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.udev.%sExecQueue()", stop ? "Stop" : "Start");

        m->stop_exec_queue = stop;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_stop_exec_queue(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return update_exec_queue(link, parameters, userdata, /* stop = */ true);
}

static int vl_method_start_exec_queue(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return update_exec_queue(link, parameters, userdata, /* stop = */ false);
}

static int vl_method_set_environment(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                {"assignments", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, SD_JSON_MANDATORY},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **assignments = NULL;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &assignments);
        if (r < 0)
                return r;

        log_debug("Received io.systemd.udev.SetEnvironment()");

        r = manager_set_environment(m, assignments);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_unset_environment(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                {"names", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, SD_JSON_MANDATORY},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **names = NULL;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &names);
        if (r < 0)
                return r;

        log_debug("Received io.systemd.udev.UnsetEnvironment()");

        r = manager_unset_environment(m, names);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_children_max(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                {"n", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64, 0, SD_JSON_MANDATORY},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        uint64_t n;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &n);
        if (r < 0)
                return r;

        log_debug("Received io.systemd.udev.SetChildrenMax(%" PRIu64 ")", n);

        manager_set_children_max(m, n);

        return sd_varlink_reply(link, NULL);
}

int udev_varlink_connect(sd_varlink **ret) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(ret);

        r = sd_varlink_connect_address(&link, UDEV_VARLINK_ADDRESS);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to " UDEV_VARLINK_ADDRESS ": %m");

        (void) sd_varlink_set_description(link, "udev");
        (void) sd_varlink_set_relative_timeout(link, USEC_INFINITY);

        *ret = TAKE_PTR(link);

        return 0;
}

int udev_varlink_call(sd_varlink *link, const char *method, sd_json_variant *parameters, sd_json_variant **ret_parameters) {
        const char *error;
        int r;

        assert(link);
        assert(method);

        r = sd_varlink_call(link, method, parameters, ret_parameters, &error);
        if (r < 0)
                return log_error_errno(r, "Failed to execute varlink call: %m");
        if (error)
                return log_error_errno(SYNTHETIC_ERRNO(EBADE),
                                       "Failed to execute varlink call: %s", error);

        return 0;
}

int manager_open_varlink(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->varlink_server);

        r = sd_varlink_server_new(&m->varlink_server, SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return r;

        sd_varlink_server_set_userdata(m->varlink_server, m);

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.service.Ping", varlink_method_ping,
                        "io.systemd.service.Reload", vl_method_reload,
                        "io.systemd.service.SetLogLevel", vl_method_set_log_level,

                        "io.systemd.udev.SetChildrenMax", vl_method_set_children_max,
                        "io.systemd.udev.SetEnvironment", vl_method_set_environment,
                        "io.systemd.udev.UnsetEnvironment", vl_method_unset_environment,
                        "io.systemd.udev.StartExecQueue", vl_method_start_exec_queue,
                        "io.systemd.udev.StopExecQueue",  vl_method_stop_exec_queue);
        if (r < 0)
                return r;

        r = sd_varlink_server_listen_address(m->varlink_server, UDEV_VARLINK_ADDRESS, 0600);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}
