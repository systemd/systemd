/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <string.h>

#include "logind.h"
#include "logind-seat.h"
#include "dbus-common.h"
#include "util.h"

#define BUS_SEAT_INTERFACE \
        " <interface name=\"org.freedesktop.login1.Seat\">\n"           \
        "  <method name=\"Terminate\"/>\n"                              \
        "  <method name=\"ActivateSession\">\n"                         \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "  </method>\n"                                                 \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"ActiveSession\" type=\"so\" access=\"read\"/>\n" \
        "  <property name=\"CanMultiSession\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"CanTTY\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"CanGraphical\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Sessions\" type=\"a(so)\" access=\"read\"/>\n" \
        "  <property name=\"IdleHint\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"IdleSinceHint\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"IdleSinceHintMonotonic\" type=\"t\" access=\"read\"/>\n" \
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
        _cleanup_free_ char *p = NULL;

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
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &path))
                return -ENOMEM;

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

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(so)", &sub))
                return -ENOMEM;

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                _cleanup_free_ char *p = NULL;

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                        return -ENOMEM;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &session->id) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p))
                        return -ENOMEM;

                if (!dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_can_multi_session(DBusMessageIter *i, const char *property, void *data) {
        Seat *s = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(s);

        b = seat_can_multi_session(s);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_can_tty(DBusMessageIter *i, const char *property, void *data) {
        Seat *s = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(s);

        b = seat_can_tty(s);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_can_graphical(DBusMessageIter *i, const char *property, void *data) {
        Seat *s = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(s);

        b = seat_can_graphical(s);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_idle_hint(DBusMessageIter *i, const char *property, void *data) {
        Seat *s = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(s);

        b = seat_get_idle_hint(s, NULL) > 0;
        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_seat_append_idle_hint_since(DBusMessageIter *i, const char *property, void *data) {
        Seat *s = data;
        dual_timestamp t;
        uint64_t k;

        assert(i);
        assert(property);
        assert(s);

        seat_get_idle_hint(s, &t);
        k = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &k))
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

static const BusProperty bus_login_seat_properties[] = {
        { "Id",                     bus_property_append_string,      "s", offsetof(Seat, id), true },
        { "ActiveSession",          bus_seat_append_active,       "(so)", 0 },
        { "CanMultiSession",        bus_seat_append_can_multi_session, "b", 0 },
        { "CanTTY",                 bus_seat_append_can_tty,         "b", 0 },
        { "CanGraphical",           bus_seat_append_can_graphical,   "b", 0 },
        { "Sessions",               bus_seat_append_sessions,    "a(so)", 0 },
        { "IdleHint",               bus_seat_append_idle_hint,       "b", 0 },
        { "IdleSinceHint",          bus_seat_append_idle_hint_since, "t", 0 },
        { "IdleSinceHintMonotonic", bus_seat_append_idle_hint_since, "t", 0 },
        { NULL, }
};

static DBusHandlerResult seat_message_dispatch(
                Seat *s,
                DBusConnection *connection,
                DBusMessage *message) {

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;

        assert(s);
        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.login1.Seat", "Terminate")) {

                r = seat_stop_sessions(s);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Seat", "ActivateSession")) {
                const char *name;
                Session *session;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session = hashmap_get(s->manager->sessions, name);
                if (!session || session->seat != s)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = session_activate(session);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;
        } else {
                const BusBoundProperties bps[] = {
                        { "org.freedesktop.login1.Seat", bus_login_seat_properties, s },
                        { NULL, }
                };
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, bps);
        }

        if (reply) {
                if (!bus_maybe_send_reply(connection, message, reply))
                        goto oom;
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
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
        _cleanup_free_ char *t;

        assert(s);

        t = bus_path_escape(s->id);
        if (!t)
                return NULL;

        return strappend("/org/freedesktop/login1/seat/", t);
}

int seat_send_signal(Seat *s, bool new_seat) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;

        assert(s);

        m = dbus_message_new_signal("/org/freedesktop/login1",
                                    "org.freedesktop.login1.Manager",
                                    new_seat ? "SeatNew" : "SeatRemoved");
        if (!m)
                return -ENOMEM;

        p = seat_bus_path(s);
        if (!p)
                return -ENOMEM;

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &s->id,
                            DBUS_TYPE_OBJECT_PATH, &p,
                            DBUS_TYPE_INVALID))
                return -ENOMEM;

        if (!dbus_connection_send(s->manager->bus, m, NULL))
                return -ENOMEM;

        return 0;
}

int seat_send_changed(Seat *s, const char *properties) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;

        assert(s);

        if (!s->started)
                return 0;

        p = seat_bus_path(s);
        if (!p)
                return -ENOMEM;

        m = bus_properties_changed_new(p, "org.freedesktop.login1.Seat", properties);
        if (!m)
                return -ENOMEM;

        if (!dbus_connection_send(s->manager->bus, m, NULL))
                return -ENOMEM;

        return 0;
}
