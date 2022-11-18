/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "udev-manager.h"
#include "udev-varlink.h"

static int vl_method_ping(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        assert(link);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.udev.Ping");

        return varlink_reply(link, NULL);
}

static int vl_method_set_log_level(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        JsonVariant *v;
        int64_t log_level;

        assert(link);
        assert(parameters);

        if (json_variant_elements(parameters) != 2)
                return varlink_error_invalid_parameter(link, parameters);

        v = json_variant_by_key(parameters, "log-level");

        if (!v || !json_variant_is_integer(v))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("log-level"));

        log_level = json_variant_integer(v);

        log_debug("Received io.systemd.udev.SetLogLevel(%" PRIi64 ")", log_level);

        if (log_level != log_get_max_level()) {
                log_set_max_level(log_level);
                m->log_level = log_level;
                manager_kill_workers(m, false);
        }

        return varlink_reply(link, NULL);
}

static int update_exec_queue(Varlink *link, JsonVariant *parameters, void *userdata, bool stop) {
        Manager *m = ASSERT_PTR(userdata);

        assert(link);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        log_debug("Received io.systemd.udev.%sExecQueue", stop ? "Stop" : "Start");

        m->stop_exec_queue = stop;

        return varlink_reply(link, NULL);
}

static int vl_method_stop_exec_queue(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        return update_exec_queue(link, parameters, userdata, /* stop = */ true);
}

static int vl_method_start_exec_queue(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        return update_exec_queue(link, parameters, userdata, /* stop = */ false);
}

int udev_varlink_connect(Varlink **ret_link) {
        _cleanup_(varlink_flush_close_unrefp) Varlink *link = NULL;
        int r;

        assert(ret_link);

        r = varlink_connect_address(&link, UDEV_VARLINK_ADDRESS);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to " UDEV_VARLINK_ADDRESS ": %m");

        (void) varlink_set_description(link, "udev");
        (void) varlink_set_relative_timeout(link, USEC_INFINITY);

        *ret_link = TAKE_PTR(link);

        return 0;
}

int udev_varlink_call(Varlink *link, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters) {
        const char *error;
        int r;

        assert(link);
        assert(method);

        r = varlink_call(link, method, parameters, ret_parameters, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to execute varlink call: %m");
        if (error)
                return log_error_errno(SYNTHETIC_ERRNO(EBADE),
                                       "Failed to execute varlink call: %s", error);

        return 0;
}

int udev_open_varlink(Manager *m) {
        int r;

        assert(m);

        r = varlink_server_new(&m->varlink_server, VARLINK_SERVER_ROOT_ONLY|VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return r;

        varlink_server_set_userdata(m->varlink_server, m);

        r = varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.udev.Ping", vl_method_ping,
                        "io.systemd.udev.SetLogLevel", vl_method_set_log_level,
                        "io.systemd.udev.StartExecQueue", vl_method_start_exec_queue,
                        "io.systemd.udev.StopExecQueue", vl_method_stop_exec_queue);

        r = varlink_server_listen_address(m->varlink_server, UDEV_VARLINK_ADDRESS, 0600);
        if (r < 0)
                return r;

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}
