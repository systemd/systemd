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
#include "dbus-common.h"

#define BUS_MANAGER_INTERFACE                                           \
        " <interface name=\"org.freedesktop.login1.Manager\">\n"        \
        "  <method name=\"GetSession\">\n"                              \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "   <arg name=\"session\" type=\"o\" direction=\"out\"/>\n"     \
        "  </method>\n"                                                 \
        "  <method name=\"GetUser\">\n"                                 \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"user\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"GetSeat\">\n"                                 \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "   <arg name=\"seat\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"ListSessions\">\n"                            \
        "   <arg name=\"users\" type=\"a(sussso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"ListUsers\">\n"                               \
        "   <arg name=\"users\" type=\"a(uso)\" direction=\"out\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"ListSeats\">\n"                               \
        "   <arg name=\"seats\" type=\"a(so)\" direction=\"out\"/>\n"   \
        "  </method>\n"                                                 \
        "  <method name=\"CreateSession\">\n"                           \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"leader\" type=\"u\" direction=\"in\"/>\n"       \
        "   <arg name=\"type\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"seat\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"tty\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"display\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"remote\" type=\"b\" direction=\"in\"/>\n"       \
        "   <arg name=\"remote_user\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"remote_host\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"controllers\" type=\"as\" direction=\"in\"/>\n" \
        "   <arg name=\"reset_controllers\" type=\"as\" direction=\"in\"/>\n" \
        "   <arg name=\"kill_processes\" type=\"as\" direction=\"in\"/>\n" \
        "   <arg name=\"id\" type=\"s\" direction=\"out\"/>\n"          \
        "   <arg name=\"path\" type=\"o\" direction=\"out\"/>\n"        \
        "   <arg name=\"fd\" type=\"h\" direction=\"out\"/>\n"          \
        "  </method>\n"                                                 \
        "  <method name=\"ActivateSession\">\n"                         \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"TerminateSession\">\n"                        \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"TerminateUser\">\n"                           \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "  </method>\n"                                                 \
        "  <method name=\"TerminateSeat\">\n"                           \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <signal name=\"SessionNew\">\n"                              \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"SessionRemoved\">\n"                          \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"UserNew\">\n"                                 \
        "   <arg name=\"uid\" type=\"u\"/>\n"                           \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"UserRemoved\">\n"                             \
        "   <arg name=\"uid\" type=\"u\"/>\n"                           \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"SeatNew\">\n"                                 \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"SeatRemoved\">\n"                             \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <property name=\"ControlGroupHierarchy\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Controllers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ResetControllers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"NAutoVTs\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"KillOnlyUsers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"KillExcludeUsers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"KillUserProcesses\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"IdleHint\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"IdleSinceHint\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"IdleSinceHintMonotonic\" type=\"t\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION_BEGIN                                             \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_MANAGER_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE

#define INTROSPECTION_END                                               \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.login1.Manager\0"

static int bus_manager_append_idle_hint(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        bool b;

        assert(i);
        assert(property);
        assert(m);

        b = manager_get_idle_hint(m, NULL);
        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_idle_hint_since(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        dual_timestamp t;
        uint64_t u;

        assert(i);
        assert(property);
        assert(m);

        manager_get_idle_hint(m, &t);
        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult manager_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;

        const BusProperty properties[] = {
                { "org.freedesktop.login1.Manager", "ControlGroupHierarchy",  bus_property_append_string,   "s",  m->cgroup_path          },
                { "org.freedesktop.login1.Manager", "Controllers",            bus_property_append_strv,     "as", m->controllers          },
                { "org.freedesktop.login1.Manager", "ResetControllers",       bus_property_append_strv,     "as", m->reset_controllers    },
                { "org.freedesktop.login1.Manager", "NAutoVTs",               bus_property_append_unsigned, "u",  &m->n_autovts           },
                { "org.freedesktop.login1.Manager", "KillOnlyUsers",          bus_property_append_strv,     "as", m->kill_only_users      },
                { "org.freedesktop.login1.Manager", "KillExcludeUsers",       bus_property_append_strv,     "as", m->kill_exclude_users   },
                { "org.freedesktop.login1.Manager", "KillUserProcesses",      bus_property_append_bool,     "b",  &m->kill_user_processes },
                { "org.freedesktop.login1.Manager", "IdleHint",               bus_manager_append_idle_hint, "b",  m                       },
                { "org.freedesktop.login1.Manager", "IdleSinceHint",          bus_manager_append_idle_hint_since, "t", m                  },
                { "org.freedesktop.login1.Manager", "IdleSinceHintMonotonic", bus_manager_append_idle_hint_since, "t", m                  },
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusError error;
        DBusMessage *reply = NULL;
        int r;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "GetSession")) {
                const char *name;
                char *p;
                Session *session;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session = hashmap_get(m->sessions, name);
                if (!session)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                p = session_bus_path(session);
                if (!p)
                        goto oom;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_OBJECT_PATH, &p,
                                DBUS_TYPE_INVALID);
                free(p);

                if (!b)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "GetUser")) {
                uint32_t uid;
                char *p;
                User *user;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &uid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
                if (!user)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                p = user_bus_path(user);
                if (!p)
                        goto oom;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_OBJECT_PATH, &p,
                                DBUS_TYPE_INVALID);
                free(p);

                if (!b)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "GetSeat")) {
                const char *name;
                char *p;
                Seat *seat;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                seat = hashmap_get(m->seats, name);
                if (!seat)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                p = seat_bus_path(seat);
                if (!p)
                        goto oom;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_OBJECT_PATH, &p,
                                DBUS_TYPE_INVALID);
                free(p);

                if (!b)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ActivateSession")) {
                const char *name;
                Session *session;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session = hashmap_get(m->sessions, name);
                if (!session)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = session_activate(session);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "TerminateSession")) {
                const char *name;
                Session *session;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session = hashmap_get(m->sessions, name);
                if (!session)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = session_stop(session);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "TerminateUser")) {
                uint32_t uid;
                User *user;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &uid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
                if (!user)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = user_stop(user);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "TerminateSeat")) {
                const char *name;
                Seat *seat;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                seat = hashmap_get(m->seats, name);
                if (!seat)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = seat_stop_sessions(seat);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                char *introspection = NULL;
                FILE *f;
                Iterator i;
                Session *session;
                Seat *seat;
                User *user;
                size_t size;
                char *p;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                /* We roll our own introspection code here, instead of
                 * relying on bus_default_message_handler() because we
                 * need to generate our introspection string
                 * dynamically. */

                if (!(f = open_memstream(&introspection, &size)))
                        goto oom;

                fputs(INTROSPECTION_BEGIN, f);

                HASHMAP_FOREACH(seat, m->seats, i) {
                        p = bus_path_escape(seat->id);

                        if (p) {
                                fprintf(f, "<node name=\"seat/%s\"/>", p);
                                free(p);
                        }
                }

                HASHMAP_FOREACH(user, m->users, i)
                        fprintf(f, "<node name=\"user/%llu\"/>", (unsigned long long) user->uid);

                HASHMAP_FOREACH(session, m->sessions, i) {
                        p = bus_path_escape(session->id);

                        if (p) {
                                fprintf(f, "<node name=\"session/%s\"/>", p);
                                free(p);
                        }
                }

                fputs(INTROSPECTION_END, f);

                if (ferror(f)) {
                        fclose(f);
                        free(introspection);
                        goto oom;
                }

                fclose(f);

                if (!introspection)
                        goto oom;

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection, DBUS_TYPE_INVALID)) {
                        free(introspection);
                        goto oom;
                }

                free(introspection);
        } else
                return bus_default_message_handler(connection, message, NULL, INTERFACES_LIST, properties);

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

const DBusObjectPathVTable bus_manager_vtable = {
        .message_function = manager_message_handler
};
