/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "strv.h"
#include "udev-manager.h"
#include "udev-varlink.h"
#include "varlink-io.systemd.Udev.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

#define UDEV_VARLINK_ADDRESS "/run/udev/io.systemd.Udev"

static int vl_method_reload(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.service.Reload()");
        manager_reload(userdata, /* force = */ true);
        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_log_level(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r, level;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "level", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_log_level, 0, SD_JSON_MANDATORY },
                {}
        };

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.service.SetLogLevel(%i)", level);
        manager_set_log_level(userdata, level);
        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_trace(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        bool enable;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "enable", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, 0, SD_JSON_MANDATORY },
                {}
        };

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &enable);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.service.SetTrace(%s)", yes_no(enable));
        manager_set_trace(userdata, enable);
        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_children_max(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        unsigned n;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "number", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, 0, SD_JSON_MANDATORY },
                {}
        };

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &n);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.Udev.SetChildrenMax(%u)", n);
        manager_set_children_max(userdata, n);
        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_environment(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "assignments", SD_JSON_VARIANT_ARRAY, json_dispatch_strv_environment, 0, SD_JSON_MANDATORY },
                {}
        };

        assert(link);

        _cleanup_strv_free_ char **v = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &v);
        if (r != 0)
                return r;

        log_debug("Received io.systemd.Udev.SetEnvironment()");
        manager_set_environment(userdata, v);
        return sd_varlink_reply(link, NULL);
}

static int vl_method_start_stop_exec_queue(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        const char *method;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_get_current_method(link, &method);
        if (r < 0)
                return r;

        log_debug("Received %s()", method);
        manager->stop_exec_queue = streq(method, "io.systemd.Udev.StopExecQueue");
        return sd_varlink_reply(link, NULL);
}

static int vl_method_exit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        /* Refuse further connections. */
        _unused_ _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *v = sd_varlink_ref(link);

        log_debug("Received io.systemd.udev.Exit()");
        manager_exit(userdata);
        return sd_varlink_reply(link, NULL);
}

int manager_start_varlink_server(Manager *manager) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *v = NULL;
        int r;

        assert(manager);
        assert(manager->event);

        r = varlink_server_new(&v, SD_VARLINK_SERVER_ROOT_ONLY | SD_VARLINK_SERVER_INHERIT_USERDATA, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        /* This needs to be after the inotify and uevent handling, to make sure that the ping is send back
         * after fully processing the pending uevents (including the synthetic ones we may create due to
         * inotify events). */
        r = sd_varlink_server_attach_event(v, manager->event, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink connection to event loop: %m");

        r = sd_varlink_server_listen_auto(v);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink socket: %m");
        if (r == 0) {
                r = sd_varlink_server_listen_address(v, UDEV_VARLINK_ADDRESS, 0600);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to Varlink socket: %m");
        }

        r = sd_varlink_server_add_interface_many(
                        v,
                        &vl_interface_io_systemd_service,
                        &vl_interface_io_systemd_Udev);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        v,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.Reload",         vl_method_reload,
                        "io.systemd.service.SetLogLevel",    vl_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment,
                        "io.systemd.Udev.SetTrace",          vl_method_set_trace,
                        "io.systemd.Udev.SetChildrenMax",    vl_method_set_children_max,
                        "io.systemd.Udev.SetEnvironment",    vl_method_set_environment,
                        "io.systemd.Udev.StartExecQueue",    vl_method_start_stop_exec_queue,
                        "io.systemd.Udev.StopExecQueue",     vl_method_start_stop_exec_queue,
                        "io.systemd.Udev.Exit",              vl_method_exit);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        manager->varlink_server = TAKE_PTR(v);
        return 0;
}

int udev_varlink_connect(sd_varlink **ret, usec_t timeout) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(ret);

        r = sd_varlink_connect_address(&link, UDEV_VARLINK_ADDRESS);
        if (r < 0)
                return r;

        (void) sd_varlink_set_description(link, "udev");

        r = sd_varlink_set_relative_timeout(link, timeout);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(link);
        return 0;
}
