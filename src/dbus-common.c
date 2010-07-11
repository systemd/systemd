/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
#include <dbus/dbus.h>

#include "log.h"
#include "dbus-common.h"

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

int bus_connect(DBusBusType t, DBusConnection **_bus, bool *private, DBusError *error) {
        DBusConnection *bus;

        assert(_bus);

        /* If we are root, then let's not go via the bus */
        if (geteuid() == 0 && t == DBUS_BUS_SYSTEM) {

                if (!(bus = dbus_connection_open_private("unix:abstract=/org/freedesktop/systemd1/private", error)))
                        return -EIO;

                if (bus_check_peercred(bus) < 0) {
                        dbus_connection_unref(bus);

                        dbus_set_error_const(error, DBUS_ERROR_ACCESS_DENIED, "Failed to verify owner of bus.");
                        return -EACCES;
                }

                if (private)
                        *private = true;

        } else {
                if (!(bus = dbus_bus_get_private(t, error)))
                        return -EIO;

                if (private)
                        *private = false;
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        *_bus = bus;
        return 0;
}
