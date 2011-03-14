/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dbus/dbus.h>

#include "log.h"
#include "dbus-common.h"
#include "util.h"

int bus_check_peercred(DBusConnection *c) {
        int fd;
        struct ucred ucred;
        socklen_t l;

        assert(c);

        assert_se(dbus_connection_get_unix_fd(c, &fd));

        l = sizeof(struct ucred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0) {
                log_error("SO_PEERCRED failed: %m");
                return -errno;
        }

        if (l != sizeof(struct ucred)) {
                log_error("SO_PEERCRED returned wrong size.");
                return -E2BIG;
        }

        if (ucred.uid != 0)
                return -EPERM;

        return 1;
}

#define TIMEOUT_USEC (60*USEC_PER_SEC)

static int sync_auth(DBusConnection *bus, DBusError *error) {
        usec_t begin, tstamp;

        assert(bus);

        /* This complexity should probably move into D-Bus itself:
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=35189 */

        begin = tstamp = now(CLOCK_MONOTONIC);
        for (;;) {

                if (tstamp > begin + TIMEOUT_USEC)
                        break;

                if (dbus_connection_get_is_authenticated(bus))
                        break;

                if (!dbus_connection_read_write_dispatch(bus, ((begin + TIMEOUT_USEC - tstamp) + USEC_PER_MSEC - 1) / USEC_PER_MSEC))
                        break;

                tstamp = now(CLOCK_MONOTONIC);
        }

        if (!dbus_connection_get_is_connected(bus)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_SERVER, "Connection terminated during authentication.");
                return -ECONNREFUSED;
        }

        if (!dbus_connection_get_is_authenticated(bus)) {
                dbus_set_error_const(error, DBUS_ERROR_TIMEOUT, "Failed to authenticate in time.");
                return -EACCES;
        }

        return 0;
}

int bus_connect(DBusBusType t, DBusConnection **_bus, bool *private, DBusError *error) {
        DBusConnection *bus;
        int r;

        assert(_bus);

        /* If we are root, then let's not go via the bus */
        if (geteuid() == 0 && t == DBUS_BUS_SYSTEM) {

                if (!(bus = dbus_connection_open_private("unix:path=/dev/.run/systemd/private", error))) {
#ifndef LEGACY
                        dbus_error_free(error);

                        /* Retry with the pre v21 socket name, to ease upgrades */
                        if (!(bus = dbus_connection_open_private("unix:abstract=/org/freedesktop/systemd1/private", error)))
#endif
                                return -EIO;
                }

                dbus_connection_set_exit_on_disconnect(bus, FALSE);

                if (bus_check_peercred(bus) < 0) {
                        dbus_connection_close(bus);
                        dbus_connection_unref(bus);

                        dbus_set_error_const(error, DBUS_ERROR_ACCESS_DENIED, "Failed to verify owner of bus.");
                        return -EACCES;
                }

                if (private)
                        *private = true;

        } else {
                if (!(bus = dbus_bus_get_private(t, error)))
                        return -EIO;

                dbus_connection_set_exit_on_disconnect(bus, FALSE);

                if (private)
                        *private = false;
        }

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

int bus_connect_system_ssh(const char *user, const char *host, DBusConnection **_bus, DBusError *error) {
        DBusConnection *bus;
        char *p = NULL;
        int r;

        assert(_bus);
        assert(user || host);

        if (user && host)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s@%s,argv3=systemd-stdio-bridge", user, host);
        else if (user)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s@localhost,argv3=systemd-stdio-bridge", user);
        else if (host)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s,argv3=systemd-stdio-bridge", host);

        if (!p) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return -ENOMEM;
        }

        bus = dbus_connection_open_private(p, error);
        free(p);

        if (!bus)
                return -EIO;

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        if (!dbus_bus_register(bus, error)) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

int bus_connect_system_polkit(DBusConnection **_bus, DBusError *error) {
        DBusConnection *bus;
        int r;

        assert(_bus);

        /* Don't bother with PolicyKit if we are root */
        if (geteuid() == 0)
                return bus_connect(DBUS_BUS_SYSTEM, _bus, NULL, error);

        if (!(bus = dbus_connection_open_private("exec:path=pkexec,argv1=" SYSTEMD_STDIO_BRIDGE_BINARY_PATH, error)))
                return -EIO;

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        if (!dbus_bus_register(bus, error)) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

const char *bus_error_message(const DBusError *error) {
        assert(error);

        /* Sometimes the D-Bus server is a little bit too verbose with
         * its error messages, so let's override them here */
        if (dbus_error_has_name(error, DBUS_ERROR_ACCESS_DENIED))
                return "Access denied";

        return error->message;
}
