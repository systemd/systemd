/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Dan Walsh

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

#include <dbus.h>

void selinux_access_free(void);

int selinux_access_check(DBusConnection *connection, DBusMessage *message, const char *path, const char *permission, DBusError *error);

#ifdef HAVE_SELINUX

#define SELINUX_ACCESS_CHECK(connection, message, permission) \
        do {                                                            \
                DBusError _error;                                       \
                int _r;                                                 \
                DBusConnection *_c = (connection);                      \
                DBusMessage *_m = (message);                            \
                dbus_error_init(&_error);                               \
                _r = selinux_access_check(_c, _m, NULL, (permission), &_error); \
                if (_r < 0)                                             \
                        return bus_send_error_reply(_c, _m, &_error, _r); \
        } while (false)

#define SELINUX_UNIT_ACCESS_CHECK(unit, connection, message, permission) \
        do {                                                            \
                DBusError _error;                                       \
                int _r;                                                 \
                DBusConnection *_c = (connection);                      \
                DBusMessage *_m = (message);                            \
                Unit *_u = (unit);                                      \
                dbus_error_init(&_error);                               \
                _r = selinux_access_check(_c, _m, _u->source_path ?: _u->fragment_path, (permission), &_error); \
                if (_r < 0)                                             \
                        return bus_send_error_reply(_c, _m, &_error, _r); \
        } while (false)

#else

#define SELINUX_ACCESS_CHECK(connection, message, permission) do { } while (false)
#define SELINUX_UNIT_ACCESS_CHECK(unit, connection, message, permission) do { } while (false)

#endif
