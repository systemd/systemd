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
#include <string.h>

#include "logind.h"
#include "logind-session.h"
#include "dbus-common.h"
#include "util.h"

#define BUS_SESSION_INTERFACE \
        " <interface name=\"org.freedesktop.login1.Session\">\n"        \
        "  <method name=\"Terminate\"/>\n"                              \
        "  <method name=\"Activate\"/>\n"                               \
        "  <method name=\"Lock\"/>\n"                                   \
        "  <method name=\"Unlock\"/>\n"                                 \
        "  <method name=\"SetIdleHint\">\n"                             \
        "   <arg name=\"b\" type=\"b\"/>\n"                             \
        "  </method>\n"                                                 \
        "  <property name=\"Id\" type=\"u\" access=\"read\"/>\n"        \
        "  <property name=\"User\" type=\"(uo)\" access=\"read\"/>\n"   \
        "  <property name=\"Name\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Timestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"TimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ControlGroupPath\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"VTNr\" type=\"u\" access=\"read\"/>\n"      \
        "  <property name=\"Seat\" type=\"(so)\" access=\"read\"/>\n"   \
        "  <property name=\"TTY\" type=\"s\" access=\"read\"/>\n"       \
        "  <property name=\"Display\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Remote\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"RemoteHost\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RemoteUser\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Service\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Leader\" type=\"u\" access=\"read\"/>\n"    \
        "  <property name=\"Audit\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Active\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"Controllers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ResetControllers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"KillProcesses\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"IdleHint\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"IdleSinceHint\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"IdleSinceHintMonotonic\" type=\"t\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_SESSION_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.login1.Session\0"

static int bus_session_append_seat(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        Session *s = data;
        const char *id, *path;
        char *p = NULL;

        assert(i);
        assert(property);
        assert(s);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        if (s->seat) {
                id = s->seat->id;
                path = p = seat_bus_path(s->seat);

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

static int bus_session_append_user(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        Session *s = data;
        char *p = NULL;

        assert(i);
        assert(property);
        assert(s);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        p = user_bus_path(s->user);
        if (!p)
                return -ENOMEM;

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &s->user->uid) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p)) {
                free(p);
                return -ENOMEM;
        }

        free(p);

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_session_append_active(DBusMessageIter *i, const char *property, void *data) {
        Session *s = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(s);

        b = session_is_active(s);
        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_session_append_idle_hint(DBusMessageIter *i, const char *property, void *data) {
        Session *s = data;
        int b;

        assert(i);
        assert(property);
        assert(s);

        b = session_get_idle_hint(s, NULL) > 0;
        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_session_append_idle_hint_since(DBusMessageIter *i, const char *property, void *data) {
        Session *s = data;
        dual_timestamp t;
        uint64_t u;

        assert(i);
        assert(property);
        assert(s);

        session_get_idle_hint(s, &t);
        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_session_append_type, session_type, SessionType);

static int get_session_for_path(Manager *m, const char *path, Session **_s) {
        Session *s;
        char *id;

        assert(m);
        assert(path);
        assert(_s);

        if (!startswith(path, "/org/freedesktop/login1/session/"))
                return -EINVAL;

        id = bus_path_unescape(path + 32);
        if (!id)
                return -ENOMEM;

        s = hashmap_get(m->sessions, id);
        free(id);

        if (!s)
                return -ENOENT;

        *_s = s;
        return 0;
}

static DBusHandlerResult session_message_dispatch(
                Session *s,
                DBusConnection *connection,
                DBusMessage *message) {

        const BusProperty properties[] = {
                { "org.freedesktop.login1.Session", "Id",                 bus_property_append_string,   "s",    s->id                   },
                { "org.freedesktop.login1.Session", "User",               bus_session_append_user,      "(uo)", s                       },
                { "org.freedesktop.login1.Session", "Name",               bus_property_append_string,   "s",    s->user->name           },
                { "org.freedesktop.login1.Session", "Timestamp",          bus_property_append_usec,     "t",    &s->timestamp.realtime  },
                { "org.freedesktop.login1.Session", "TimestampMonotonic", bus_property_append_usec,     "t",    &s->timestamp.monotonic },
                { "org.freedesktop.login1.Session", "ControlGroupPath",   bus_property_append_string,   "s",    s->cgroup_path          },
                { "org.freedesktop.login1.Session", "VTNr",               bus_property_append_uint32,   "u",    &s->vtnr                },
                { "org.freedesktop.login1.Session", "Seat",               bus_session_append_seat,      "(so)", s                       },
                { "org.freedesktop.login1.Session", "TTY",                bus_property_append_string,   "s",    s->tty                  },
                { "org.freedesktop.login1.Session", "Display",            bus_property_append_string,   "s",    s->display              },
                { "org.freedesktop.login1.Session", "Remote",             bus_property_append_bool,     "b",    &s->remote              },
                { "org.freedesktop.login1.Session", "RemoteUser",         bus_property_append_string,   "s",    s->remote_user          },
                { "org.freedesktop.login1.Session", "RemoteHost",         bus_property_append_string,   "s",    s->remote_host          },
                { "org.freedesktop.login1.Session", "Service",            bus_property_append_string,   "s",    s->service              },
                { "org.freedesktop.login1.Session", "Leader",             bus_property_append_pid,      "u",    &s->leader              },
                { "org.freedesktop.login1.Session", "Audit",              bus_property_append_uint32,   "u",    &s->audit_id            },
                { "org.freedesktop.login1.Session", "Type",               bus_session_append_type,      "s",    &s->type                },
                { "org.freedesktop.login1.Session", "Active",             bus_session_append_active,    "b",    s                       },
                { "org.freedesktop.login1.Session", "Controllers",        bus_property_append_strv,     "as",   s->controllers          },
                { "org.freedesktop.login1.Session", "ResetControllers",   bus_property_append_strv,     "as",   s->reset_controllers    },
                { "org.freedesktop.login1.Session", "KillProcesses",      bus_property_append_bool,     "b",    &s->kill_processes      },
                { "org.freedesktop.login1.Session", "IdleHint",           bus_session_append_idle_hint, "b",    s                       },
                { "org.freedesktop.login1.Session", "IdleSinceHint",          bus_session_append_idle_hint_since, "t", s                },
                { "org.freedesktop.login1.Session", "IdleSinceHintMonotonic", bus_session_append_idle_hint_since, "t", s                },
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusError error;
        DBusMessage *reply = NULL;
        int r;

        assert(s);
        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "Terminate")) {

                r = session_stop(s);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "Activate")) {

                r = session_activate(s);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "Lock") ||
                   dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "Unlock")) {
                bool b;
                DBusMessage *sig;

                sig = dbus_message_new_signal(dbus_message_get_path(message), "org.freedesktop.login1.Session", dbus_message_get_member(message));
                if (!sig)
                        goto oom;

                b = dbus_connection_send(connection, sig, NULL);
                dbus_message_unref(sig);

                if (!b)
                        goto oom;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "SetIdleHint")) {
                dbus_bool_t b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_BOOLEAN, &b,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session_set_idle_hint(s, b);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, properties);

        if (reply) {
                if (!dbus_connection_send(connection, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult session_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;
        Session *s;
        int r;

        r = get_session_for_path(m, dbus_message_get_path(message), &s);
        if (r < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT) {
                        DBusError e;

                        dbus_error_init(&e);
                        dbus_set_error_const(&e, DBUS_ERROR_UNKNOWN_OBJECT, "Unknown session");
                        return bus_send_error_reply(connection, message, &e, r);
                }

                return bus_send_error_reply(connection, message, NULL, r);
        }

        return session_message_dispatch(s, connection, message);
}

const DBusObjectPathVTable bus_session_vtable = {
        .message_function = session_message_handler
};

char *session_bus_path(Session *s) {
        char *t, *r;

        assert(s);

        t = bus_path_escape(s->id);
        if (!t)
                return NULL;

        r = strappend("/org/freedesktop/login1/session/", t);
        free(t);

        return r;
}

int session_send_signal(Session *s, bool new_session) {
        DBusMessage *m;
        int r = -ENOMEM;
        char *p = NULL;

        assert(s);

        m = dbus_message_new_signal("/org/freedesktop/login1",
                                    "org.freedesktop.login1.Manager",
                                    new_session ? "SessionNew" : "SessionRemoved");

        if (!m)
                return -ENOMEM;

        p = session_bus_path(s);
        if (!p)
                goto finish;

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &s->id,
                            DBUS_TYPE_OBJECT_PATH, &p,
                            DBUS_TYPE_INVALID))
                goto finish;

        if (!dbus_connection_send(s->manager->bus, m, NULL))
                goto finish;

        r = 0;

finish:
        dbus_message_unref(m);
        free(p);

        return r;
}

int session_send_changed(Session *s, const char *properties) {
        DBusMessage *m;
        int r = -ENOMEM;
        char *p = NULL;

        assert(s);

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        m = bus_properties_changed_new(p, "org.freedesktop.login1.Session", properties);
        if (!m)
                goto finish;

        if (!dbus_connection_send(s->manager->bus, m, NULL))
                goto finish;

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);
        free(p);

        return r;
}
