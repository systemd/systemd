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
        "  <method name=\"Kill\">\n"                                    \
        "   <arg name=\"who\" type=\"s\"/>\n"                           \
        "   <arg name=\"signal\" type=\"s\"/>\n"                        \
        "  </method>\n"                                                 \
        "  <signal name=\"Lock\"/>\n"                                   \
        "  <signal name=\"Unlock\"/>\n"                                 \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"User\" type=\"(uo)\" access=\"read\"/>\n"   \
        "  <property name=\"Name\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Timestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"TimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"DefaultControlGroup\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"VTNr\" type=\"u\" access=\"read\"/>\n"      \
        "  <property name=\"Seat\" type=\"(so)\" access=\"read\"/>\n"   \
        "  <property name=\"TTY\" type=\"s\" access=\"read\"/>\n"       \
        "  <property name=\"Display\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Remote\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"RemoteHost\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RemoteUser\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Service\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Leader\" type=\"u\" access=\"read\"/>\n"    \
        "  <property name=\"Audit\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"Type\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Class\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"Active\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"State\" type=\"s\" access=\"read\"/>\n"     \
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
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &path))
                return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_session_append_user(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        User *u = data;
        _cleanup_free_ char *p = NULL;

        assert(i);
        assert(property);
        assert(u);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        p = user_bus_path(u);
        if (!p)
                return -ENOMEM;

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &u->uid) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p))
                return -ENOMEM;

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
        int r;

        assert(i);
        assert(property);
        assert(s);

        r = session_get_idle_hint(s, &t);
        if (r < 0)
                return r;

        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

static int bus_session_append_default_cgroup(DBusMessageIter *i, const char *property, void *data) {
        Session *s = data;
        _cleanup_free_ char *t = NULL;
        int r;
        bool success;

        assert(i);
        assert(property);
        assert(s);

        r = cg_join_spec(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, &t);
        if (r < 0)
                return r;

        success = dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t);
        return success ? 0 : -ENOMEM;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_session_append_type, session_type, SessionType);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_session_append_class, session_class, SessionClass);

static int bus_session_append_state(DBusMessageIter *i, const char *property, void *data) {
        Session *s = data;
        const char *state;

        assert(i);
        assert(property);
        assert(s);

        state = session_state_to_string(session_get_state(s));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

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

static const BusProperty bus_login_session_properties[] = {
        { "Id",                     bus_property_append_string,         "s", offsetof(Session, id),                 true },
        { "Timestamp",              bus_property_append_usec,           "t", offsetof(Session, timestamp.realtime)  },
        { "TimestampMonotonic",     bus_property_append_usec,           "t", offsetof(Session, timestamp.monotonic) },
        { "DefaultControlGroup",    bus_session_append_default_cgroup,  "s", 0,                                     },
        { "VTNr",                   bus_property_append_uint32,         "u", offsetof(Session, vtnr)                },
        { "Seat",                   bus_session_append_seat,         "(so)", 0 },
        { "TTY",                    bus_property_append_string,         "s", offsetof(Session, tty),                true },
        { "Display",                bus_property_append_string,         "s", offsetof(Session, display),            true },
        { "Remote",                 bus_property_append_bool,           "b", offsetof(Session, remote)              },
        { "RemoteUser",             bus_property_append_string,         "s", offsetof(Session, remote_user),        true },
        { "RemoteHost",             bus_property_append_string,         "s", offsetof(Session, remote_host),        true },
        { "Service",                bus_property_append_string,         "s", offsetof(Session, service),            true },
        { "Leader",                 bus_property_append_pid,            "u", offsetof(Session, leader)              },
        { "Audit",                  bus_property_append_uint32,         "u", offsetof(Session, audit_id)            },
        { "Type",                   bus_session_append_type,            "s", offsetof(Session, type)                },
        { "Class",                  bus_session_append_class,           "s", offsetof(Session, class)               },
        { "Active",                 bus_session_append_active,          "b", 0 },
        { "State",                  bus_session_append_state,           "s", 0 },
        { "Controllers",            bus_property_append_strv,          "as", offsetof(Session, controllers),        true },
        { "ResetControllers",       bus_property_append_strv,          "as", offsetof(Session, reset_controllers),  true },
        { "KillProcesses",          bus_property_append_bool,           "b", offsetof(Session, kill_processes)      },
        { "IdleHint",               bus_session_append_idle_hint,       "b", 0 },
        { "IdleSinceHint",          bus_session_append_idle_hint_since, "t", 0 },
        { "IdleSinceHintMonotonic", bus_session_append_idle_hint_since, "t", 0 },
        { NULL, }
};

static const BusProperty bus_login_session_user_properties[] = {
        { "User",                   bus_session_append_user,         "(uo)", 0 },
        { "Name",                   bus_property_append_string,         "s", offsetof(User, name),                  true },
        { NULL, }
};

static DBusHandlerResult session_message_dispatch(
                Session *s,
                DBusConnection *connection,
                DBusMessage *message) {

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
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

                if (session_send_lock(s, streq(dbus_message_get_member(message), "Lock")) < 0)
                        goto oom;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "SetIdleHint")) {
                dbus_bool_t b;
                unsigned long ul;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_BOOLEAN, &b,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                ul = dbus_bus_get_unix_user(connection, dbus_message_get_sender(message), &error);
                if (ul == (unsigned long) -1)
                        return bus_send_error_reply(connection, message, &error, -EIO);

                if (ul != 0 && ul != s->user->uid)
                        return bus_send_error_reply(connection, message, NULL, -EPERM);

                session_set_idle_hint(s, b);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Session", "Kill")) {
                const char *swho;
                int32_t signo;
                KillWho who;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &swho,
                                    DBUS_TYPE_INT32, &signo,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(swho))
                        who = KILL_ALL;
                else {
                        who = kill_who_from_string(swho);
                        if (who < 0)
                                return bus_send_error_reply(connection, message, &error, -EINVAL);
                }

                if (signo <= 0 || signo >= _NSIG)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = session_kill(s, who, signo);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else {
                const BusBoundProperties bps[] = {
                        { "org.freedesktop.login1.Session", bus_login_session_properties,      s       },
                        { "org.freedesktop.login1.Session", bus_login_session_user_properties, s->user },
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
        _cleanup_free_ char *t;

        assert(s);

        t = bus_path_escape(s->id);
        if (!t)
                return NULL;

        return strappend("/org/freedesktop/login1/session/", t);
}

int session_send_signal(Session *s, bool new_session) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;

        assert(s);

        m = dbus_message_new_signal("/org/freedesktop/login1",
                                    "org.freedesktop.login1.Manager",
                                    new_session ? "SessionNew" : "SessionRemoved");

        if (!m)
                return -ENOMEM;

        p = session_bus_path(s);
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

int session_send_changed(Session *s, const char *properties) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;

        assert(s);

        if (!s->started)
                return 0;

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        m = bus_properties_changed_new(p, "org.freedesktop.login1.Session", properties);
        if (!m)
                return -ENOMEM;

        if (!dbus_connection_send(s->manager->bus, m, NULL))
                return -ENOMEM;

        return 0;
}

int session_send_lock(Session *s, bool lock) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        bool b;
        _cleanup_free_ char *p = NULL;

        assert(s);

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        m = dbus_message_new_signal(p, "org.freedesktop.login1.Session", lock ? "Lock" : "Unlock");

        if (!m)
                return -ENOMEM;

        b = dbus_connection_send(s->manager->bus, m, NULL);
        if (!b)
                return -ENOMEM;

        return 0;
}

int session_send_lock_all(Manager *m, bool lock) {
        Session *session;
        Iterator i;
        int r = 0;

        assert(m);

        HASHMAP_FOREACH(session, m->sessions, i) {
                int k;

                k = session_send_lock(session, lock);
                if (k < 0)
                        r = k;
        }

        return r;
}
