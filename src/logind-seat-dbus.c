/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>

#include "logind.h"
#include "logind-seat.h"
#include "dbus-common.h"
#include "util.h"

#define BUS_SEAT_INTERFACE \
        " <interface name=\"org.freedesktop.login1.Seat\">\n"           \
        "  <method name=\"Terminate\"/>\n"                              \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"Active\" type=\"so\" access=\"read\"/>\n"   \
        "  <property name=\"Sessions\" type=\"a(so)\" access=\"read\"/>\n" \
        " </interface>\n"                                               \

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_SEAT_INTERFACE                                              \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.login1.Seat\0"

static int bus_seat_append_active(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        Seat *s = data;
        const char *id, *path;
        char *p = NULL;

        assert(i);
        assert(property);
        assert(s);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        if (s->active) {
                id = s->active->id;
                path = p = session_bus_path(s->active);

                if (!p)
                        return -ENOMEM;
        } else {
                id = "";
                path = "/";
        }

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &id) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &path)) {
                free(p);
                return -ENOMEM;
        }

        free(p);

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_sessions(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub, sub2;
        Seat *s = data;
        Session *session;

        assert(i);
        assert(property);
        assert(s);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "so", &sub))
                return -ENOMEM;

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                char *p;

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                        return -ENOMEM;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &session->id) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p)) {
                        free(p);
                        return -ENOMEM;
                }

                free(p);

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int get_seat_for_path(Manager *m, const char *path, Seat **_s) {
        Seat *s;
        char *id;

        assert(m);
        assert(path);
        assert(_s);

        if (!startswith(path, "/org/freedesktop/login1/seat/"))
                return -EINVAL;

        id = bus_path_unescape(path + 29);
        if (!id)
                return -ENOMEM;

        s = hashmap_get(m->seats, id);
        free(id);

        if (!s)
                return -ENOENT;

        *_s = s;
        return 0;
}

static DBusHandlerResult seat_message_dispatch(
                Seat *s,
                DBusConnection *connection,
                DBusMessage *message) {

        const BusProperty properties[] = {
                { "org.freedesktop.login1.Seat", "Id",       bus_property_append_string, "s",     s->id },
                { "org.freedesktop.login1.Seat", "Active",   bus_seat_append_active,     "(so)",  s     },
                { "org.freedesktop.login1.Seat", "Sessions", bus_seat_append_sessions,   "a(so)", s     },
                { NULL, NULL, NULL, NULL, NULL }
        };

        assert(s);
        assert(connection);
        assert(message);

        return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, properties);
}

static DBusHandlerResult seat_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;
        Seat *s;
        int r;

        r = get_seat_for_path(m, dbus_message_get_path(message), &s);
        if (r < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT) {
                        DBusError e;

                        dbus_error_init(&e);
                        dbus_set_error_const(&e, DBUS_ERROR_UNKNOWN_OBJECT, "Unknown seat");
                        return bus_send_error_reply(connection, message, &e, r);
                }

                return bus_send_error_reply(connection, message, NULL, r);
        }

        return seat_message_dispatch(s, connection, message);
}

const DBusObjectPathVTable bus_seat_vtable = {
        .message_function = seat_message_handler
};

char *seat_bus_path(Seat *s) {
        char *t, *r;

        assert(s);

        t = bus_path_escape(s->id);
        if (!t)
                return NULL;

        r = strappend("/org/freedesktop/login1/seat/", t);
        free(t);

        return r;
}
