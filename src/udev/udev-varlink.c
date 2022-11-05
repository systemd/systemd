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
                        "io.systemd.udev.Ping", vl_method_ping);

        r = varlink_server_listen_address(m->varlink_server, UDEV_VARLINK_ADDRESS, 0600);
        if (r < 0)
                return r;

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}
