/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "udev-manager.h"
#include "udev-varlink.h"
#include "varlink-io.systemd.service.h"

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

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.service.Ping", varlink_method_ping);
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
