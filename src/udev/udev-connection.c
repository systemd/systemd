/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "udev-connection.h"
#include "udev-varlink.h"

int udev_connection_init(UdevConnection *conn, usec_t timeout) {
        int r;

        assert(conn);

        r = udev_varlink_connect(&conn->link);
        if (r >= 0) {
                r = sd_varlink_set_relative_timeout(conn->link, timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to apply timeout: %m");

                return 0;
        }

        log_warning("Failed to initialize varlink connection, falling back to legacy udev control: %m");

        r = udev_ctrl_new(&conn->uctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev control: %m");

        conn->timeout = timeout;

        return 0;
}

void udev_connection_done(UdevConnection *conn) {
        if (!conn)
                return;

        conn->link = sd_varlink_flush_close_unref(conn->link);
        conn->uctrl = udev_ctrl_unref(conn->uctrl);
}

int udev_connection_wait(UdevConnection *conn) {
        assert(conn);
        assert(!conn->link != !conn->uctrl);

        if (conn->uctrl)
                return udev_ctrl_wait(conn->uctrl, conn->timeout);

        return 0;
}

int udev_connection_send_ping(UdevConnection *conn) {
        assert(conn);
        assert(!conn->link != !conn->uctrl);

        if (conn->uctrl)
                return udev_ctrl_send_ping(conn->uctrl);

        return udev_varlink_call(conn->link, "io.systemd.service.Ping", NULL, NULL);

        return 0;
}
