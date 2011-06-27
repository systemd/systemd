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
#include <unistd.h>

#include "logind.h"
#include "dbus-common.h"
#include "strv.h"

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
        "   <arg name=\"sessions\" type=\"a(susso)\" direction=\"out\"/>\n" \
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
        "   <arg name=\"sevice\" type=\"s\" direction=\"in\"/>\n"       \
        "   <arg name=\"type\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"seat\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"vtnr\" type=\"u\" direction=\"in\"/>\n"         \
        "   <arg name=\"tty\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"display\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"remote\" type=\"b\" direction=\"in\"/>\n"       \
        "   <arg name=\"remote_user\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"remote_host\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"controllers\" type=\"as\" direction=\"in\"/>\n" \
        "   <arg name=\"reset_controllers\" type=\"as\" direction=\"in\"/>\n" \
        "   <arg name=\"kill_processes\" type=\"b\" direction=\"in\"/>\n" \
        "   <arg name=\"id\" type=\"s\" direction=\"out\"/>\n"          \
        "   <arg name=\"path\" type=\"o\" direction=\"out\"/>\n"        \
        "   <arg name=\"runtime_path\" type=\"o\" direction=\"out\"/>\n" \
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
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(m);

        b = manager_get_idle_hint(m, NULL) > 0;
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

static int bus_manager_create_session(Manager *m, DBusMessage *message, DBusMessage **_reply) {
        Session *session = NULL;
        User *user = NULL;
        const char *type, *seat, *tty, *display, *remote_user, *remote_host, *service;
        uint32_t uid, leader, audit_id = 0;
        dbus_bool_t remote, kill_processes;
        char **controllers = NULL, **reset_controllers = NULL;
        SessionType t;
        Seat *s;
        DBusMessageIter iter;
        int r;
        char *id = NULL, *p;
        uint32_t vtnr = 0;
        int pipe_fds[2] = { -1, -1 };
        DBusMessage *reply = NULL;
        bool b;

        assert(m);
        assert(message);
        assert(_reply);

        if (!dbus_message_iter_init(message, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &uid);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &leader);

        if (leader <= 0 ||
            !dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &service);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &type);
        t = session_type_from_string(type);

        if (t < 0 ||
            !dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &seat);

        if (isempty(seat))
                s = NULL;
        else {
                s = hashmap_get(m->seats, seat);
                if (!s)
                        return -ENOENT;
        }

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &vtnr);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &tty);

        if (tty_is_vc(tty)) {
                int v;

                if (!s)
                        s = m->vtconsole;
                else if (s != m->vtconsole)
                        return -EINVAL;

                v = vtnr_from_tty(tty);

                if (v <= 0)
                        return v < 0 ? v : -EINVAL;

                if (vtnr <= 0)
                        vtnr = (uint32_t) v;
                else if (vtnr != (uint32_t) v)
                        return -EINVAL;

        } else if (!isempty(tty) && seat_is_vtconsole(s))
                return -EINVAL;

        if (s) {
                if (seat_is_vtconsole(s)) {
                        if (vtnr <= 0 || vtnr > 63)
                                return -EINVAL;
                } else {
                        if (vtnr > 0)
                                return -EINVAL;
                }
        }

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &display);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &remote);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &remote_user);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &remote_host);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        r = bus_parse_strv_iter(&iter, &controllers);
        if (r < 0)
                return -EINVAL;

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRING) {
                r = -EINVAL;
                goto fail;
        }

        r = bus_parse_strv_iter(&iter, &reset_controllers);
        if (r < 0)
                goto fail;

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN) {
                r = -EINVAL;
                goto fail;
        }

        dbus_message_iter_get_basic(&iter, &kill_processes);

        r = manager_add_user_by_uid(m, uid, &user);
        if (r < 0)
                goto fail;

        audit_session_from_pid(leader, &audit_id);

        if (audit_id > 0) {
                asprintf(&id, "%lu", (unsigned long) audit_id);

                if (!id) {
                        r = -ENOMEM;
                        goto fail;
                }

                session = hashmap_get(m->sessions, id);

                if (session) {

                        /* Session already exists, client is probably
                         * something like "su" which changes uid but
                         * is still the same audit session */

                        reply = dbus_message_new_method_return(message);
                        if (!reply) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        /* Create a throw-away fd */
                        if (pipe(pipe_fds) < 0) {
                                r = -errno;
                                goto fail;
                        }

                        close_nointr_nofail(pipe_fds[0]);
                        pipe_fds[0] = -1;

                        p = session_bus_path(session);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        b = dbus_message_append_args(
                                        reply,
                                        DBUS_TYPE_STRING, &session->id,
                                        DBUS_TYPE_OBJECT_PATH, &p,
                                        DBUS_TYPE_STRING, &session->user->runtime_path,
                                        DBUS_TYPE_UNIX_FD, &pipe_fds[1],
                                        DBUS_TYPE_INVALID);
                        free(p);

                        if (!b) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        close_nointr_nofail(pipe_fds[1]);
                        *_reply = reply;

                        return 0;
                }

        } else {
                do {
                        free(id);
                        asprintf(&id, "c%lu", ++m->session_counter);

                        if (!id) {
                                r = -ENOMEM;
                                goto fail;
                        }

                } while (hashmap_get(m->sessions, id));
        }

        r = manager_add_session(m, user, id, &session);
        free(id);
        if (r < 0)
                goto fail;

        session->leader = leader;
        session->audit_id = audit_id;
        session->type = t;
        session->remote = remote;
        session->controllers = controllers;
        session->reset_controllers = reset_controllers;
        session->kill_processes = kill_processes;
        session->vtnr = vtnr;

        controllers = reset_controllers = NULL;

        if (!isempty(tty)) {
                session->tty = strdup(tty);
                if (!session->tty) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(display)) {
                session->display = strdup(display);
                if (!session->display) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(remote_user)) {
                session->remote_user = strdup(remote_user);
                if (!session->remote_user) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(remote_host)) {
                session->remote_host = strdup(remote_host);
                if (!session->remote_host) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(service)) {
                session->service = strdup(service);
                if (!session->service) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (pipe(pipe_fds) < 0) {
                r = -errno;
                goto fail;
        }

        r = session_set_pipe_fd(session, pipe_fds[0]);
        if (r < 0)
                goto fail;
        pipe_fds[0] = -1;

        if (s) {
                r = seat_attach_session(s, session);
                if (r < 0)
                        goto fail;
        }

        r = session_start(session);
        if (r < 0)
                goto fail;

        reply = dbus_message_new_method_return(message);
        if (!reply) {
                r = -ENOMEM;
                goto fail;
        }

        p = session_bus_path(session);
        if (!p) {
                r = -ENOMEM;
                goto fail;
        }

        b = dbus_message_append_args(
                        reply,
                        DBUS_TYPE_STRING, &session->id,
                        DBUS_TYPE_OBJECT_PATH, &p,
                        DBUS_TYPE_STRING, &session->user->runtime_path,
                        DBUS_TYPE_UNIX_FD, &pipe_fds[1],
                        DBUS_TYPE_INVALID);
        free(p);

        if (!b) {
                r = -ENOMEM;
                goto fail;
        }

        close_nointr_nofail(pipe_fds[1]);
        *_reply = reply;

        return 0;

fail:
        strv_free(controllers);
        strv_free(reset_controllers);

        if (session)
                session_add_to_gc_queue(session);

        if (user)
                user_add_to_gc_queue(user);

        close_pipe(pipe_fds);

        if (reply)
                dbus_message_unref(reply);

        return r;
}

static DBusHandlerResult manager_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;

        const BusProperty properties[] = {
                { "org.freedesktop.login1.Manager", "ControlGroupHierarchy",  bus_property_append_string,   "s",  m->cgroup_path          },
                { "org.freedesktop.login1.Manager", "Controllers",            bus_property_append_strv,     "as", m->controllers          },
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListSessions")) {
                char *p;
                Session *session;
                Iterator i;
                DBusMessageIter iter, sub;
                const char *empty = "";

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(susso)", &sub))
                        goto oom;

                HASHMAP_FOREACH(session, m->sessions, i) {
                        DBusMessageIter sub2;
                        uint32_t uid;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        uid = session->user->uid;

                        p = session_bus_path(session);
                        if (!p)
                                goto oom;

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &session->id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &uid) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &session->user->name) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, session->seat ? (const char**) &session->seat->id : &empty) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p)) {
                                free(p);
                                goto oom;
                        }

                        free(p);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListUsers")) {
                char *p;
                User *user;
                Iterator i;
                DBusMessageIter iter, sub;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(uso)", &sub))
                        goto oom;

                HASHMAP_FOREACH(user, m->users, i) {
                        DBusMessageIter sub2;
                        uint32_t uid;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        uid = user->uid;

                        p = user_bus_path(user);
                        if (!p)
                                goto oom;

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &uid) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &user->name) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p)) {
                                free(p);
                                goto oom;
                        }

                        free(p);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListSeats")) {
                char *p;
                Seat *seat;
                Iterator i;
                DBusMessageIter iter, sub;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(so)", &sub))
                        goto oom;

                HASHMAP_FOREACH(seat, m->seats, i) {
                        DBusMessageIter sub2;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        p = seat_bus_path(seat);
                        if (!p)
                                goto oom;

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &seat->id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p)) {
                                free(p);
                                goto oom;
                        }

                        free(p);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CreateSession")) {

                r = bus_manager_create_session(m, message, &reply);
                if (r == -ENOMEM)
                        goto oom;

                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

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

DBusHandlerResult bus_message_filter(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;
        DBusError error;

        assert(m);
        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Agent", "Released")) {
                const char *cgroup;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &cgroup,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse Released message: %s", bus_error_message(&error));
                else
                        manager_cgroup_notify_empty(m, cgroup);
        }

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int manager_send_changed(Manager *manager, const char *properties) {
        DBusMessage *m;
        int r = -ENOMEM;

        assert(manager);

        m = bus_properties_changed_new("/org/freedesktop/login1", "org.freedesktop.login1.Manager", properties);
        if (!m)
                goto finish;

        if (!dbus_connection_send(manager->bus, m, NULL))
                goto finish;

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        return r;
}
