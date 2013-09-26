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
#include <unistd.h>
#include <pwd.h>

#include "logind.h"
#include "dbus-common.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "polkit.h"
#include "special.h"
#include "sleep-config.h"
#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"
#include "fileio-label.h"
#include "label.h"
#include "utf8.h"
#include "unit-name.h"
#include "bus-errors.h"
#include "virt.h"

#define BUS_MANAGER_INTERFACE                                           \
        " <interface name=\"org.freedesktop.login1.Manager\">\n"        \
        "  <method name=\"GetSession\">\n"                              \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "   <arg name=\"session\" type=\"o\" direction=\"out\"/>\n"     \
        "  </method>\n"                                                 \
        "  <method name=\"GetSessionByPID\">\n"                         \
        "   <arg name=\"pid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"session\" type=\"o\" direction=\"out\"/>\n"     \
        "  </method>\n"                                                 \
        "  <method name=\"GetUser\">\n"                                 \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"user\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"GetUserByPID\">\n"                            \
        "   <arg name=\"pid\" type=\"u\" direction=\"in\"/>\n"          \
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
        "   <arg name=\"service\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"type\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"class\" type=\"s\" direction=\"in\"/>\n"        \
        "   <arg name=\"seat\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"vtnr\" type=\"u\" direction=\"in\"/>\n"         \
        "   <arg name=\"tty\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"display\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"remote\" type=\"b\" direction=\"in\"/>\n"       \
        "   <arg name=\"remote_user\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"remote_host\" type=\"s\" direction=\"in\"/>\n"  \
        "   <arg name=\"scope_properties\" type=\"a(sv)\" direction=\"in\"/>\n" \
        "   <arg name=\"id\" type=\"s\" direction=\"out\"/>\n"          \
        "   <arg name=\"path\" type=\"o\" direction=\"out\"/>\n"        \
        "   <arg name=\"runtime_path\" type=\"o\" direction=\"out\"/>\n" \
        "   <arg name=\"fd\" type=\"h\" direction=\"out\"/>\n"          \
        "   <arg name=\"seat\" type=\"s\" direction=\"out\"/>\n"        \
        "   <arg name=\"vtnr\" type=\"u\" direction=\"out\"/>\n"        \
        "   <arg name=\"existing\" type=\"b\" direction=\"out\"/>\n"    \
        "  </method>\n"                                                 \
        "  <method name=\"ReleaseSession\">\n"                          \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"ActivateSession\">\n"                         \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"ActivateSessionOnSeat\">\n"                   \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "   <arg name=\"seat\" type=\"s\" direction=\"in\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"LockSession\">\n"                             \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"UnlockSession\">\n"                           \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <method name=\"LockSessions\"/>\n"                           \
        "  <method name=\"UnlockSessions\"/>\n"                         \
        "  <method name=\"KillSession\">\n"                             \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "   <arg name=\"who\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"signal\" type=\"s\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"KillUser\">\n"                                \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"signal\" type=\"s\" direction=\"in\"/>\n"       \
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
        "  <method name=\"SetUserLinger\">\n"                           \
        "   <arg name=\"uid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"b\" type=\"b\" direction=\"in\"/>\n"            \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"AttachDevice\">\n"                            \
        "   <arg name=\"seat\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"sysfs\" type=\"s\" direction=\"in\"/>\n"        \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"FlushDevices\">\n"                            \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"PowerOff\">\n"                                \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"Reboot\">\n"                                  \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"Suspend\">\n"                                 \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"Hibernate\">\n"                               \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"HybridSleep\">\n"                             \
        "   <arg name=\"interactive\" type=\"b\" direction=\"in\"/>\n"  \
        "  </method>\n"                                                 \
        "  <method name=\"CanPowerOff\">\n"                             \
        "   <arg name=\"result\" type=\"s\" direction=\"out\"/>\n"      \
        "  </method>\n"                                                 \
        "  <method name=\"CanReboot\">\n"                               \
        "   <arg name=\"result\" type=\"s\" direction=\"out\"/>\n"      \
        "  </method>\n"                                                 \
        "  <method name=\"CanSuspend\">\n"                              \
        "   <arg name=\"result\" type=\"s\" direction=\"out\"/>\n"      \
        "  </method>\n"                                                 \
        "  <method name=\"CanHibernate\">\n"                            \
        "   <arg name=\"result\" type=\"s\" direction=\"out\"/>\n"      \
        "  </method>\n"                                                 \
        "  <method name=\"CanHybridSleep\">\n"                          \
        "   <arg name=\"result\" type=\"s\" direction=\"out\"/>\n"      \
        "  </method>\n"                                                 \
        "  <method name=\"Inhibit\">\n"                                 \
        "   <arg name=\"what\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"who\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"why\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"fd\" type=\"h\" direction=\"out\"/>\n"          \
        "  </method>\n"                                                 \
        "  <method name=\"ListInhibitors\">\n"                          \
        "   <arg name=\"inhibitors\" type=\"a(ssssuu)\" direction=\"out\"/>\n" \
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
        "  <signal name=\"PrepareForShutdown\">\n"                      \
        "   <arg name=\"active\" type=\"b\"/>\n"                        \
        "  </signal>\n"                                                 \
        "  <signal name=\"PrepareForSleep\">\n"                         \
        "   <arg name=\"active\" type=\"b\"/>\n"                        \
        "  </signal>\n"                                                 \
        "  <property name=\"NAutoVTs\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"KillOnlyUsers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"KillExcludeUsers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"KillUserProcesses\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"IdleHint\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"IdleSinceHint\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"IdleSinceHintMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"BlockInhibited\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"DelayInhibited\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"InhibitDelayMaxUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"HandlePowerKey\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"HandleSuspendKey\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"HandleHibernateKey\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"HandleLidSwitch\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"IdleAction\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"IdleActionUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"PreparingForShutdown\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"PreparingForSleep\" type=\"b\" access=\"read\"/>\n" \
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

static int bus_manager_append_inhibited(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        InhibitWhat w;
        const char *p;

        w = manager_inhibit_what(m, streq(property, "BlockInhibited") ? INHIBIT_BLOCK : INHIBIT_DELAY);
        p = inhibit_what_to_string(w);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &p))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_preparing(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        dbus_bool_t b;

        assert(i);
        assert(property);

        if (streq(property, "PreparingForShutdown"))
                b = !!(m->action_what & INHIBIT_SHUTDOWN);
        else
                b = !!(m->action_what & INHIBIT_SLEEP);

        dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b);
        return 0;
}

static int bus_manager_create_session(Manager *m, DBusMessage *message) {

        const char *type, *class, *cseat, *tty, *display, *remote_user, *remote_host, *service;
        uint32_t uid, leader, audit_id = 0;
        _cleanup_free_ char *id = NULL;
        Session *session = NULL;
        User *user = NULL;
        Seat *seat = NULL;
        DBusMessageIter iter;
        dbus_bool_t remote;
        uint32_t vtnr = 0;
        SessionType t;
        SessionClass c;
        bool b;
        int r;

        assert(m);
        assert(message);

        if (!dbus_message_iter_init(message, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &uid);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &leader);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &service);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &type);
        if (isempty(type))
                t = _SESSION_TYPE_INVALID;
        else {
                t = session_type_from_string(type);
                if (t < 0)
                        return -EINVAL;
        }

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &class);
        if (isempty(class))
                c = _SESSION_CLASS_INVALID;
        else {
                c = session_class_from_string(class);
                if (c < 0)
                        return -EINVAL;
        }

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &cseat);

        if (isempty(cseat))
                seat = NULL;
        else {
                seat = hashmap_get(m->seats, cseat);
                if (!seat)
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

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return -EINVAL;

                v = vtnr_from_tty(tty);

                if (v <= 0)
                        return v < 0 ? v : -EINVAL;

                if (vtnr <= 0)
                        vtnr = (uint32_t) v;
                else if (vtnr != (uint32_t) v)
                        return -EINVAL;
        } else if (tty_is_console(tty)) {

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return -EINVAL;

                if (vtnr != 0)
                        return -EINVAL;
        }

        if (seat) {
                if (seat_has_vts(seat)) {
                        if (vtnr > 63)
                                return -EINVAL;
                } else {
                        if (vtnr != 0)
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

        if (t == _SESSION_TYPE_INVALID) {
                if (!isempty(display))
                        t = SESSION_X11;
                else if (!isempty(tty))
                        t = SESSION_TTY;
                else
                        t = SESSION_UNSPECIFIED;
        }

        if (c == _SESSION_CLASS_INVALID) {
                if (!isempty(display) || !isempty(tty))
                        c = SESSION_USER;
                else
                        c = SESSION_BACKGROUND;
        }

        dbus_message_iter_get_basic(&iter, &remote);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &remote_user);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &remote_host);

        if (leader <= 0) {
                leader = bus_get_unix_process_id(m->bus, dbus_message_get_sender(message), NULL);
                if (leader == 0)
                        return -EINVAL;
        }

        r = manager_get_session_by_pid(m, leader, &session);
        if (session) {
                _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
                _cleanup_free_ char *path = NULL;
                _cleanup_close_ int fifo_fd = -1;
                dbus_bool_t exists;

                /* Session already exists, client is probably
                 * something like "su" which changes uid but is still
                 * the same session */

                fifo_fd = session_create_fifo(session);
                if (fifo_fd < 0) {
                        r = fifo_fd;
                        goto fail;
                }

                path = session_bus_path(session);
                if (!path) {
                        r = -ENOMEM;
                        goto fail;
                }

                reply = dbus_message_new_method_return(message);
                if (!reply) {
                        r = -ENOMEM;
                        goto fail;
                }

                cseat = session->seat ? session->seat->id : "";
                vtnr = session->vtnr;
                exists = true;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_STRING, &session->id,
                                DBUS_TYPE_OBJECT_PATH, &path,
                                DBUS_TYPE_STRING, &session->user->runtime_path,
                                DBUS_TYPE_UNIX_FD, &fifo_fd,
                                DBUS_TYPE_STRING, &cseat,
                                DBUS_TYPE_UINT32, &vtnr,
                                DBUS_TYPE_BOOLEAN, &exists,
                                DBUS_TYPE_INVALID);
                if (!b) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (!dbus_connection_send(m->bus, reply, NULL)) {
                        r = -ENOMEM;
                        goto fail;
                }

                return 0;
        }

        audit_session_from_pid(leader, &audit_id);
        if (audit_id > 0) {
                /* Keep our session IDs and the audit session IDs in sync */

                if (asprintf(&id, "%lu", (unsigned long) audit_id) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

                /* Wut? There's already a session by this name and we
                 * didn't find it above? Weird, then let's not trust
                 * the audit data and let's better register a new
                 * ID */
                if (hashmap_get(m->sessions, id)) {
                        log_warning("Existing logind session ID %s used by new audit session, ignoring", id);
                        audit_id = 0;

                        free(id);
                        id = NULL;
                }
        }

        if (!id) {
                do {
                        free(id);
                        id = NULL;

                        if (asprintf(&id, "c%lu", ++m->session_counter) < 0) {
                                r = -ENOMEM;
                                goto fail;
                        }

                } while (hashmap_get(m->sessions, id));
        }

        r = manager_add_user_by_uid(m, uid, &user);
        if (r < 0)
                goto fail;

        r = manager_add_session(m, id, &session);
        if (r < 0)
                goto fail;

        session_set_user(session, user);

        session->leader = leader;
        session->audit_id = audit_id;
        session->type = t;
        session->class = c;
        session->remote = remote;
        session->vtnr = vtnr;

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

        if (seat) {
                r = seat_attach_session(seat, session);
                if (r < 0)
                        goto fail;
        }

        r = session_start(session);
        if (r < 0)
                goto fail;

        session->create_message = dbus_message_ref(message);

        /* Now, let's wait until the slice unit and stuff got
         * created. We send the reply back from
         * session_send_create_reply().*/

        return 0;

fail:
        if (session)
                session_add_to_gc_queue(session);

        if (user)
                user_add_to_gc_queue(user);

        return r;
}

static int bus_manager_inhibit(
                Manager *m,
                DBusConnection *connection,
                DBusMessage *message,
                DBusError *error,
                DBusMessage **_reply) {

        Inhibitor *i = NULL;
        char *id = NULL;
        const char *who, *why, *what, *mode;
        pid_t pid;
        InhibitWhat w;
        InhibitMode mm;
        unsigned long ul;
        int r, fifo_fd = -1;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;

        assert(m);
        assert(connection);
        assert(message);
        assert(error);
        assert(_reply);

        if (!dbus_message_get_args(
                            message,
                            error,
                            DBUS_TYPE_STRING, &what,
                            DBUS_TYPE_STRING, &who,
                            DBUS_TYPE_STRING, &why,
                            DBUS_TYPE_STRING, &mode,
                            DBUS_TYPE_INVALID)) {
                r = -EIO;
                goto fail;
        }

        w = inhibit_what_from_string(what);
        if (w <= 0) {
                r = -EINVAL;
                goto fail;
        }

        mm = inhibit_mode_from_string(mode);
        if (mm < 0) {
                r = -EINVAL;
                goto fail;
        }

        /* Delay is only supported for shutdown/sleep */
        if (mm == INHIBIT_DELAY && (w & ~(INHIBIT_SHUTDOWN|INHIBIT_SLEEP))) {
                r = -EINVAL;
                goto fail;
        }

        /* Don't allow taking delay locks while we are already
         * executing the operation. We shouldn't create the impression
         * that the lock was successful if the machine is about to go
         * down/suspend any moment. */
        if (m->action_what & w) {
                r = -EALREADY;
                goto fail;
        }

        r = verify_polkit(connection, message,
                          w == INHIBIT_SHUTDOWN             ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-shutdown" : "org.freedesktop.login1.inhibit-delay-shutdown") :
                          w == INHIBIT_SLEEP                ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-sleep"    : "org.freedesktop.login1.inhibit-delay-sleep") :
                          w == INHIBIT_IDLE                 ? "org.freedesktop.login1.inhibit-block-idle" :
                          w == INHIBIT_HANDLE_POWER_KEY     ? "org.freedesktop.login1.inhibit-handle-power-key" :
                          w == INHIBIT_HANDLE_SUSPEND_KEY   ? "org.freedesktop.login1.inhibit-handle-suspend-key" :
                          w == INHIBIT_HANDLE_HIBERNATE_KEY ? "org.freedesktop.login1.inhibit-handle-hibernate-key" :
                                                              "org.freedesktop.login1.inhibit-handle-lid-switch",
                          false, NULL, error);
        if (r < 0)
                goto fail;

        ul = dbus_bus_get_unix_user(connection, dbus_message_get_sender(message), error);
        if (ul == (unsigned long) -1) {
                r = -EIO;
                goto fail;
        }

        pid = bus_get_unix_process_id(connection, dbus_message_get_sender(message), error);
        if (pid <= 0) {
                r = -EIO;
                goto fail;
        }

        do {
                free(id);
                id = NULL;

                if (asprintf(&id, "%lu", ++m->inhibit_counter) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }
        } while (hashmap_get(m->inhibitors, id));

        r = manager_add_inhibitor(m, id, &i);
        free(id);

        if (r < 0)
                goto fail;

        i->what = w;
        i->mode = mm;
        i->pid = pid;
        i->uid = (uid_t) ul;
        i->why = strdup(why);
        i->who = strdup(who);

        if (!i->why || !i->who) {
                r = -ENOMEM;
                goto fail;
        }

        fifo_fd = inhibitor_create_fifo(i);
        if (fifo_fd < 0) {
                r = fifo_fd;
                goto fail;
        }

        reply = dbus_message_new_method_return(message);
        if (!reply) {
                r = -ENOMEM;
                goto fail;
        }

        if (!dbus_message_append_args(
                            reply,
                            DBUS_TYPE_UNIX_FD, &fifo_fd,
                            DBUS_TYPE_INVALID)) {
                r = -ENOMEM;
                goto fail;
        }

        close_nointr_nofail(fifo_fd);
        *_reply = reply;
        reply = NULL;

        inhibitor_start(i);

        return 0;

fail:
        if (i)
                inhibitor_free(i);

        if (fifo_fd >= 0)
                close_nointr_nofail(fifo_fd);

        return r;
}

static int trigger_device(Manager *m, struct udev_device *d) {
        struct udev_enumerate *e;
        struct udev_list_entry *first, *item;
        int r;

        assert(m);

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        if (d) {
                if (udev_enumerate_add_match_parent(e, d) < 0) {
                        r = -EIO;
                        goto finish;
                }
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto finish;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                char *t;
                const char *p;

                p = udev_list_entry_get_name(item);

                t = strappend(p, "/uevent");
                if (!t) {
                        r = -ENOMEM;
                        goto finish;
                }

                write_string_file(t, "change");
                free(t);
        }

        r = 0;

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
}

static int attach_device(Manager *m, const char *seat, const char *sysfs) {
        struct udev_device *d;
        _cleanup_free_ char *rule = NULL, *file = NULL;
        const char *id_for_seat;
        int r;

        assert(m);
        assert(seat);
        assert(sysfs);

        d = udev_device_new_from_syspath(m->udev, sysfs);
        if (!d)
                return -ENODEV;

        if (!udev_device_has_tag(d, "seat")) {
                r = -ENODEV;
                goto finish;
        }

        id_for_seat = udev_device_get_property_value(d, "ID_FOR_SEAT");
        if (!id_for_seat) {
                r = -ENODEV;
                goto finish;
        }

        if (asprintf(&file, "/etc/udev/rules.d/72-seat-%s.rules", id_for_seat) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        if (asprintf(&rule, "TAG==\"seat\", ENV{ID_FOR_SEAT}==\"%s\", ENV{ID_SEAT}=\"%s\"", id_for_seat, seat) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        mkdir_p_label("/etc/udev/rules.d", 0755);
        label_init("/etc");
        r = write_string_file_atomic_label(file, rule);
        if (r < 0)
                goto finish;

        r = trigger_device(m, d);

finish:
        if (d)
                udev_device_unref(d);

        return r;
}

static int flush_devices(Manager *m) {
        _cleanup_closedir_ DIR *d;

        assert(m);

        d = opendir("/etc/udev/rules.d");
        if (!d) {
                if (errno != ENOENT)
                        log_warning("Failed to open /etc/udev/rules.d: %m");
        } else {
                struct dirent *de;

                while ((de = readdir(d))) {

                        if (!dirent_is_file(de))
                                continue;

                        if (!startswith(de->d_name, "72-seat-"))
                                continue;

                        if (!endswith(de->d_name, ".rules"))
                                continue;

                        if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                                log_warning("Failed to unlink %s: %m", de->d_name);
                }
        }

        return trigger_device(m, NULL);
}

static int have_multiple_sessions(
                Manager *m,
                uid_t uid) {

        Session *session;
        Iterator i;

        assert(m);

        /* Check for other users' sessions. Greeter sessions do not
         * count, and non-login sessions do not count either. */
        HASHMAP_FOREACH(session, m->sessions, i)
                if (session->class == SESSION_USER &&
                    !session->closing &&
                    session->user->uid != uid)
                        return true;

        return false;
}

static int bus_manager_log_shutdown(
                Manager *m,
                InhibitWhat w,
                const char *unit_name) {

        const char *p, *q;

        assert(m);
        assert(unit_name);

        if (w != INHIBIT_SHUTDOWN)
                return 0;

        if (streq(unit_name, SPECIAL_POWEROFF_TARGET)) {
                p = "MESSAGE=System is powering down.";
                q = "SHUTDOWN=power-off";
        } else if (streq(unit_name, SPECIAL_HALT_TARGET)) {
                p = "MESSAGE=System is halting.";
                q = "SHUTDOWN=halt";
        } else if (streq(unit_name, SPECIAL_REBOOT_TARGET)) {
                p = "MESSAGE=System is rebooting.";
                q = "SHUTDOWN=reboot";
        } else if (streq(unit_name, SPECIAL_KEXEC_TARGET)) {
                p = "MESSAGE=System is rebooting with kexec.";
                q = "SHUTDOWN=kexec";
        } else {
                p = "MESSAGE=System is shutting down.";
                q = NULL;
        }

        return log_struct(LOG_NOTICE, MESSAGE_ID(SD_MESSAGE_SHUTDOWN),
                          p,
                          q, NULL);
}

static int execute_shutdown_or_sleep(
                Manager *m,
                InhibitWhat w,
                const char *unit_name,
                DBusError *error) {

        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *mode = "replace-irreversibly", *p;
        int r;
        char *c;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(unit_name);

        bus_manager_log_shutdown(m, w, unit_name);

        r = bus_method_call_with_reply(
                        m->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit_name,
                        DBUS_TYPE_STRING, &mode,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_get_args(
                            reply,
                            error,
                            DBUS_TYPE_OBJECT_PATH, &p,
                            DBUS_TYPE_INVALID))
                return -EINVAL;

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        m->action_unit = unit_name;
        free(m->action_job);
        m->action_job = c;
        m->action_what = w;

        return 0;
}

static int delay_shutdown_or_sleep(
                Manager *m,
                InhibitWhat w,
                const char *unit_name) {

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(unit_name);

        m->action_timestamp = now(CLOCK_MONOTONIC);
        m->action_unit = unit_name;
        m->action_what = w;

        return 0;
}

static int bus_manager_can_shutdown_or_sleep(
                Manager *m,
                DBusConnection *connection,
                DBusMessage *message,
                InhibitWhat w,
                const char *action,
                const char *action_multiple_sessions,
                const char *action_ignore_inhibit,
                const char *sleep_verb,
                DBusError *error,
                DBusMessage **_reply) {

        bool multiple_sessions, challenge, blocked, b;
        const char *result = NULL;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        unsigned long ul;

        assert(m);
        assert(connection);
        assert(message);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);
        assert(action);
        assert(action_multiple_sessions);
        assert(action_ignore_inhibit);
        assert(error);
        assert(_reply);

        if (sleep_verb) {
                r = can_sleep(sleep_verb);
                if (r < 0)
                        return r;
                if (r == 0) {
                        result = "na";
                        goto finish;
                }
        }

        ul = dbus_bus_get_unix_user(connection, dbus_message_get_sender(message), error);
        if (ul == (unsigned long) -1)
                return -EIO;

        r = have_multiple_sessions(m, (uid_t) ul);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, (uid_t) ul);

        if (multiple_sessions) {
                r = verify_polkit(connection, message, action_multiple_sessions, false, &challenge, error);
                if (r < 0)
                        return r;

                if (r > 0)
                        result = "yes";
                else if (challenge)
                        result = "challenge";
                else
                        result = "no";
        }

        if (blocked) {
                r = verify_polkit(connection, message, action_ignore_inhibit, false, &challenge, error);
                if (r < 0)
                        return r;

                if (r > 0 && !result)
                        result = "yes";
                else if (challenge && (!result || streq(result, "yes")))
                        result = "challenge";
                else
                        result = "no";
        }

        if (!multiple_sessions && !blocked) {
                /* If neither inhibit nor multiple sessions
                 * apply then just check the normal policy */

                r = verify_polkit(connection, message, action, false, &challenge, error);
                if (r < 0)
                        return r;

                if (r > 0)
                        result = "yes";
                else if (challenge)
                        result = "challenge";
                else
                        result = "no";
        }

finish:
        reply = dbus_message_new_method_return(message);
        if (!reply)
                return -ENOMEM;

        b = dbus_message_append_args(
                        reply,
                        DBUS_TYPE_STRING, &result,
                        DBUS_TYPE_INVALID);
        if (!b)
                return -ENOMEM;

        *_reply = reply;
        reply = NULL;
        return 0;
}

static int send_prepare_for(Manager *m, InhibitWhat w, bool _active) {
        static const char * const signal_name[_INHIBIT_WHAT_MAX] = {
                [INHIBIT_SHUTDOWN] = "PrepareForShutdown",
                [INHIBIT_SLEEP] = "PrepareForSleep"
        };

        dbus_bool_t active = _active;
        _cleanup_dbus_message_unref_ DBusMessage *message = NULL;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(signal_name[w]);

        message = dbus_message_new_signal("/org/freedesktop/login1", "org.freedesktop.login1.Manager", signal_name[w]);
        if (!message)
                return -ENOMEM;

        if (!dbus_message_append_args(message, DBUS_TYPE_BOOLEAN, &active, DBUS_TYPE_INVALID) ||
            !dbus_connection_send(m->bus, message, NULL))
                return -ENOMEM;

        return 0;
}

int bus_manager_shutdown_or_sleep_now_or_later(
                Manager *m,
                const char *unit_name,
                InhibitWhat w,
                DBusError *error) {

        bool delayed;
        int r;

        assert(m);
        assert(unit_name);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);
        assert(!m->action_job);

        /* Tell everybody to prepare for shutdown/sleep */
        send_prepare_for(m, w, true);

        delayed =
                m->inhibit_delay_max > 0 &&
                manager_is_inhibited(m, w, INHIBIT_DELAY, NULL, false, false, 0);

        if (delayed)
                /* Shutdown is delayed, keep in mind what we
                 * want to do, and start a timeout */
                r = delay_shutdown_or_sleep(m, w, unit_name);
        else
                /* Shutdown is not delayed, execute it
                 * immediately */
                r = execute_shutdown_or_sleep(m, w, unit_name, error);

        return r;
}

static int bus_manager_do_shutdown_or_sleep(
                Manager *m,
                DBusConnection *connection,
                DBusMessage *message,
                const char *unit_name,
                InhibitWhat w,
                const char *action,
                const char *action_multiple_sessions,
                const char *action_ignore_inhibit,
                const char *sleep_verb,
                DBusError *error,
                DBusMessage **_reply) {

        dbus_bool_t interactive;
        bool multiple_sessions, blocked;
        DBusMessage *reply = NULL;
        int r;
        unsigned long ul;

        assert(m);
        assert(connection);
        assert(message);
        assert(unit_name);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);
        assert(action);
        assert(action_multiple_sessions);
        assert(action_ignore_inhibit);
        assert(error);
        assert(_reply);

        /* Don't allow multiple jobs being executed at the same time */
        if (m->action_what)
                return -EALREADY;

        if (!dbus_message_get_args(
                            message,
                            error,
                            DBUS_TYPE_BOOLEAN, &interactive,
                            DBUS_TYPE_INVALID))
                return -EINVAL;

        if (sleep_verb) {
                r = can_sleep(sleep_verb);
                if (r < 0)
                        return r;

                if (r == 0)
                        return -ENOTSUP;
        }

        ul = dbus_bus_get_unix_user(connection, dbus_message_get_sender(message), error);
        if (ul == (unsigned long) -1)
                return -EIO;

        r = have_multiple_sessions(m, (uid_t) ul);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, (uid_t) ul);

        if (multiple_sessions) {
                r = verify_polkit(connection, message, action_multiple_sessions, interactive, NULL, error);
                if (r < 0)
                        return r;
        }

        if (blocked) {
                r = verify_polkit(connection, message, action_ignore_inhibit, interactive, NULL, error);
                if (r < 0)
                        return r;
        }

        if (!multiple_sessions && !blocked) {
                r = verify_polkit(connection, message, action, interactive, NULL, error);
                if (r < 0)
                        return r;
        }

        r = bus_manager_shutdown_or_sleep_now_or_later(m, unit_name, w, error);
        if (r < 0)
                return r;

        reply = dbus_message_new_method_return(message);
        if (!reply)
                return -ENOMEM;

        *_reply = reply;
        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_manager_append_handle_action, handle_action, HandleAction);

static const BusProperty bus_login_manager_properties[] = {
        { "NAutoVTs",               bus_property_append_unsigned,       "u",  offsetof(Manager, n_autovts)           },
        { "KillOnlyUsers",          bus_property_append_strv,           "as", offsetof(Manager, kill_only_users),    true },
        { "KillExcludeUsers",       bus_property_append_strv,           "as", offsetof(Manager, kill_exclude_users), true },
        { "KillUserProcesses",      bus_property_append_bool,           "b",  offsetof(Manager, kill_user_processes) },
        { "IdleHint",               bus_manager_append_idle_hint,       "b",  0 },
        { "IdleSinceHint",          bus_manager_append_idle_hint_since, "t",  0 },
        { "IdleSinceHintMonotonic", bus_manager_append_idle_hint_since, "t",  0 },
        { "BlockInhibited",         bus_manager_append_inhibited,       "s",  0 },
        { "DelayInhibited",         bus_manager_append_inhibited,       "s",  0 },
        { "InhibitDelayMaxUSec",    bus_property_append_usec,           "t",  offsetof(Manager, inhibit_delay_max)   },
        { "HandlePowerKey",         bus_manager_append_handle_action,   "s",  offsetof(Manager, handle_power_key)    },
        { "HandleSuspendKey",       bus_manager_append_handle_action,   "s",  offsetof(Manager, handle_suspend_key)  },
        { "HandleHibernateKey",     bus_manager_append_handle_action,   "s",  offsetof(Manager, handle_hibernate_key)},
        { "HandleLidSwitch",        bus_manager_append_handle_action,   "s",  offsetof(Manager, handle_lid_switch)   },
        { "IdleAction",             bus_manager_append_handle_action,   "s",  offsetof(Manager, idle_action)         },
        { "IdleActionUSec",         bus_property_append_usec,           "t",  offsetof(Manager, idle_action_usec) },
        { "PreparingForShutdown",   bus_manager_append_preparing,       "b",  0 },
        { "PreparingForSleep",      bus_manager_append_preparing,       "b",  0 },
        { NULL, }
};

static DBusHandlerResult manager_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "GetSessionByPID")) {
                uint32_t pid;
                char *p;
                Session *session;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &pid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = manager_get_session_by_pid(m, pid, &session);
                if (r <= 0)
                        return bus_send_error_reply(connection, message, NULL, r < 0 ? r : -ENOENT);

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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "GetUserByPID")) {
                uint32_t pid;
                char *p;
                User *user;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &pid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = manager_get_user_by_pid(m, pid, &user);
                if (r <= 0)
                        return bus_send_error_reply(connection, message, NULL, r < 0 ? r : -ENOENT);

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
                        _cleanup_free_ char *p = NULL;
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

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListSeats")) {
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
                        _cleanup_free_ char *p = NULL;
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

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListInhibitors")) {
                Inhibitor *inhibitor;
                Iterator i;
                DBusMessageIter iter, sub;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssssuu)", &sub))
                        goto oom;

                HASHMAP_FOREACH(inhibitor, m->inhibitors, i) {
                        DBusMessageIter sub2;
                        dbus_uint32_t uid, pid;
                        const char *what, *who, *why, *mode;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        what = strempty(inhibit_what_to_string(inhibitor->what));
                        who = strempty(inhibitor->who);
                        why = strempty(inhibitor->why);
                        mode = strempty(inhibit_mode_to_string(inhibitor->mode));
                        uid = (dbus_uint32_t) inhibitor->uid;
                        pid = (dbus_uint32_t) inhibitor->pid;

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &what) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &who) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &why) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &mode) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &uid) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &pid))
                                goto oom;

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;


        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "Inhibit")) {

                r = bus_manager_inhibit(m, connection, message, &error, &reply);

                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);


        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CreateSession")) {

                r = bus_manager_create_session(m, message);

                /* Don't delay the work on OOM here, since it might be
                 * triggered by a low RLIMIT_NOFILE here (since we
                 * send a dupped fd to the client), and we'd rather
                 * see this fail quickly then be retried later */

                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ReleaseSession")) {
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

                /* We use the FIFO to detect stray sessions where the
                process invoking PAM dies abnormally. We need to make
                sure that that process is not killed if at the clean
                end of the session it closes the FIFO. Hence, with
                this call explicitly turn off the FIFO logic, so that
                the PAM code can finish clean up on its own */
                session_remove_fifo(session);

                reply = dbus_message_new_method_return(message);
                if (!reply)
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ActivateSessionOnSeat")) {
                const char *session_name, *seat_name;
                Session *session;
                Seat *seat;

                /* Same as ActivateSession() but refuses to work if
                 * the seat doesn't match */

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &session_name,
                                    DBUS_TYPE_STRING, &seat_name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                session = hashmap_get(m->sessions, session_name);
                if (!session)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                seat = hashmap_get(m->seats, seat_name);
                if (!seat)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                if (session->seat != seat)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = session_activate(session);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "LockSession") ||
                   dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "UnlockSession")) {
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
                        return bus_send_error_reply(connection, message, NULL, -ENOENT);

                if (session_send_lock(session, streq(dbus_message_get_member(message), "LockSession")) < 0)
                        goto oom;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "LockSessions") ||
                   dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "UnlockSessions")) {

                r = session_send_lock_all(m, streq(dbus_message_get_member(message), "LockSessions"));
                if (r < 0)
                        bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "KillSession")) {
                const char *swho;
                int32_t signo;
                KillWho who;
                const char *name;
                Session *session;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
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

                session = hashmap_get(m->sessions, name);
                if (!session)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = session_kill(session, who, signo);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "KillUser")) {
                uint32_t uid;
                User *user;
                int32_t signo;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &uid,
                                    DBUS_TYPE_INT32, &signo,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (signo <= 0 || signo >= _NSIG)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
                if (!user)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = user_kill(user, signo);
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "SetUserLinger")) {
                uint32_t uid;
                struct passwd *pw;
                dbus_bool_t b, interactive;
                char *path;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &uid,
                                    DBUS_TYPE_BOOLEAN, &b,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                errno = 0;
                pw = getpwuid(uid);
                if (!pw)
                        return bus_send_error_reply(connection, message, NULL, errno ? -errno : -EINVAL);

                r = verify_polkit(connection, message, "org.freedesktop.login1.set-user-linger", interactive, NULL, &error);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                mkdir_p_label("/var/lib/systemd", 0755);

                r = mkdir_safe_label("/var/lib/systemd/linger", 0755, 0, 0);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                path = strappend("/var/lib/systemd/linger/", pw->pw_name);
                if (!path)
                        goto oom;

                if (b) {
                        User *u;

                        r = touch(path);
                        free(path);

                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (manager_add_user_by_uid(m, uid, &u) >= 0)
                                user_start(u);

                } else {
                        User *u;

                        r = unlink(path);
                        free(path);

                        if (r < 0 && errno != ENOENT)
                                return bus_send_error_reply(connection, message, &error, -errno);

                        u = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
                        if (u)
                                user_add_to_gc_queue(u);
                }

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "AttachDevice")) {
                const char *sysfs, *seat;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &seat,
                                    DBUS_TYPE_STRING, &sysfs,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!path_startswith(sysfs, "/sys") || !seat_name_is_valid(seat))
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                r = verify_polkit(connection, message, "org.freedesktop.login1.attach-device", interactive, NULL, &error);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                r = attach_device(m, seat, sysfs);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;


        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "FlushDevices")) {
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = verify_polkit(connection, message, "org.freedesktop.login1.flush-devices", interactive, NULL, &error);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                r = flush_devices(m);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "PowerOff")) {

                r = bus_manager_do_shutdown_or_sleep(
                                m, connection, message,
                                SPECIAL_POWEROFF_TARGET,
                                INHIBIT_SHUTDOWN,
                                "org.freedesktop.login1.power-off",
                                "org.freedesktop.login1.power-off-multiple-sessions",
                                "org.freedesktop.login1.power-off-ignore-inhibit",
                                NULL,
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);
        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "Reboot")) {
                r = bus_manager_do_shutdown_or_sleep(
                                m, connection, message,
                                SPECIAL_REBOOT_TARGET,
                                INHIBIT_SHUTDOWN,
                                "org.freedesktop.login1.reboot",
                                "org.freedesktop.login1.reboot-multiple-sessions",
                                "org.freedesktop.login1.reboot-ignore-inhibit",
                                NULL,
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "Suspend")) {
                r = bus_manager_do_shutdown_or_sleep(
                                m, connection, message,
                                SPECIAL_SUSPEND_TARGET,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.suspend",
                                "org.freedesktop.login1.suspend-multiple-sessions",
                                "org.freedesktop.login1.suspend-ignore-inhibit",
                                "suspend",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);
        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "Hibernate")) {
                r = bus_manager_do_shutdown_or_sleep(
                                m, connection, message,
                                SPECIAL_HIBERNATE_TARGET,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.hibernate",
                                "org.freedesktop.login1.hibernate-multiple-sessions",
                                "org.freedesktop.login1.hibernate-ignore-inhibit",
                                "hibernate",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "HybridSleep")) {
                r = bus_manager_do_shutdown_or_sleep(
                                m, connection, message,
                                SPECIAL_HYBRID_SLEEP_TARGET,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.hibernate",
                                "org.freedesktop.login1.hibernate-multiple-sessions",
                                "org.freedesktop.login1.hibernate-ignore-inhibit",
                                "hybrid-sleep",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CanPowerOff")) {

                r = bus_manager_can_shutdown_or_sleep(
                                m, connection, message,
                                INHIBIT_SHUTDOWN,
                                "org.freedesktop.login1.power-off",
                                "org.freedesktop.login1.power-off-multiple-sessions",
                                "org.freedesktop.login1.power-off-ignore-inhibit",
                                NULL,
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);
        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CanReboot")) {
                r = bus_manager_can_shutdown_or_sleep(
                                m, connection, message,
                                INHIBIT_SHUTDOWN,
                                "org.freedesktop.login1.reboot",
                                "org.freedesktop.login1.reboot-multiple-sessions",
                                "org.freedesktop.login1.reboot-ignore-inhibit",
                                NULL,
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CanSuspend")) {
                r = bus_manager_can_shutdown_or_sleep(
                                m, connection, message,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.suspend",
                                "org.freedesktop.login1.suspend-multiple-sessions",
                                "org.freedesktop.login1.suspend-ignore-inhibit",
                                "suspend",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CanHibernate")) {
                r = bus_manager_can_shutdown_or_sleep(
                                m, connection, message,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.hibernate",
                                "org.freedesktop.login1.hibernate-multiple-sessions",
                                "org.freedesktop.login1.hibernate-ignore-inhibit",
                                "hibernate",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.login1.Manager", "CanHybridSleep")) {
                r = bus_manager_can_shutdown_or_sleep(
                                m, connection, message,
                                INHIBIT_SLEEP,
                                "org.freedesktop.login1.hibernate",
                                "org.freedesktop.login1.hibernate-multiple-sessions",
                                "org.freedesktop.login1.hibernate-ignore-inhibit",
                                "hybrid-sleep",
                                &error, &reply);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

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
                        fprintf(f, "<node name=\"user/_%llu\"/>", (unsigned long long) user->uid);

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
        } else {
                const BusBoundProperties bps[] = {
                        { "org.freedesktop.login1.Manager", bus_login_manager_properties, m },
                        { NULL, }
                };
                return bus_default_message_handler(connection, message, NULL, INTERFACES_LIST, bps);
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

        log_debug("Got message: %s %s %s", strna(dbus_message_get_sender(message)), strna(dbus_message_get_interface(message)), strna(dbus_message_get_member(message)));

        if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                const char *path, *result, *unit;
                uint32_t id;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_UINT32, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_STRING, &unit,
                                           DBUS_TYPE_STRING, &result,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse JobRemoved message: %s", bus_error_message(&error));
                        goto finish;
                }

                if (m->action_job && streq(m->action_job, path)) {
                        log_info("Operation finished.");

                        /* Tell people that they now may take a lock again */
                        send_prepare_for(m, m->action_what, false);

                        free(m->action_job);
                        m->action_job = NULL;
                        m->action_unit = NULL;
                        m->action_what = 0;

                } else {
                        Session *s;
                        User *u;

                        s = hashmap_get(m->session_units, unit);
                        if (s) {
                                if (streq_ptr(path, s->scope_job)) {
                                        free(s->scope_job);
                                        s->scope_job = NULL;

                                        if (s->started) {
                                                if (streq(result, "done"))
                                                        session_send_create_reply(s, NULL);
                                                else {
                                                        dbus_set_error(&error, BUS_ERROR_JOB_FAILED, "Start job for unit %s failed with '%s'", unit, result);
                                                        session_send_create_reply(s, &error);
                                                }
                                        } else
                                                session_save(s);
                                }

                                session_add_to_gc_queue(s);
                        }

                        u = hashmap_get(m->user_units, unit);
                        if (u) {
                                if (streq_ptr(path, u->service_job)) {
                                        free(u->service_job);
                                        u->service_job = NULL;
                                }

                                if (streq_ptr(path, u->slice_job)) {
                                        free(u->slice_job);
                                        u->slice_job = NULL;
                                }

                                user_save(u);
                                user_add_to_gc_queue(u);
                        }
                }

        } else if (dbus_message_is_signal(message, "org.freedesktop.DBus.Properties", "PropertiesChanged")) {

                _cleanup_free_ char *unit = NULL;
                const char *path;

                path = dbus_message_get_path(message);
                if (!path)
                        goto finish;

                unit_name_from_dbus_path(path, &unit);
                if (unit) {
                        Session *s;
                        User *u;

                        s = hashmap_get(m->session_units, unit);
                        if (s)
                                session_add_to_gc_queue(s);

                        u = hashmap_get(m->user_units, unit);
                        if (u)
                                user_add_to_gc_queue(u);
                }

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "UnitRemoved")) {

                const char *path, *unit;
                Session *session;
                User *user;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &unit,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse UnitRemoved message: %s", bus_error_message(&error));
                        goto finish;
                }

                session = hashmap_get(m->session_units, unit);
                if (session)
                         session_add_to_gc_queue(session);

                user = hashmap_get(m->user_units, unit);
                if (user)
                        user_add_to_gc_queue(user);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "Reloading")) {
                dbus_bool_t b;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_BOOLEAN, &b,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse Reloading message: %s", bus_error_message(&error));
                        goto finish;
                }

                /* systemd finished reloading, let's recheck all our sessions */
                if (!b) {
                        Session *session;
                        Iterator i;

                        log_debug("System manager has been reloaded, rechecking sessions...");

                        HASHMAP_FOREACH(session, m->sessions, i)
                                session_add_to_gc_queue(session);
                }

        } else if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
                const char *name, *old, *new;
                char *key;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_STRING, &old,
                                           DBUS_TYPE_STRING, &new,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse NameOwnerChanged message: %s", bus_error_message(&error));
                        goto finish;
                }

                /* drop all controllers owned by this name */
                if (*old && !*new && (key = hashmap_remove(m->busnames, old))) {
                        Session *session;
                        Iterator i;

                        free(key);

                        HASHMAP_FOREACH(session, m->sessions, i)
                                if (session_is_controller(session, old))
                                        session_drop_controller(session);
                }
        }

finish:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int manager_send_changed(Manager *manager, const char *properties) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;

        assert(manager);

        m = bus_properties_changed_new("/org/freedesktop/login1",
                                       "org.freedesktop.login1.Manager",
                                       properties);
        if (!m)
                return -ENOMEM;

        if (!dbus_connection_send(manager->bus, m, NULL))
                return -ENOMEM;

        return 0;
}

int manager_dispatch_delayed(Manager *manager) {
        DBusError error;
        int r;

        assert(manager);

        if (manager->action_what == 0 || manager->action_job)
                return 0;

        /* Continue delay? */
        if (manager_is_inhibited(manager, manager->action_what, INHIBIT_DELAY, NULL, false, false, 0)) {

                if (manager->action_timestamp + manager->inhibit_delay_max > now(CLOCK_MONOTONIC))
                        return 0;

                log_info("Delay lock is active but inhibitor timeout is reached.");
        }

        /* Actually do the operation */
        dbus_error_init(&error);
        r = execute_shutdown_or_sleep(manager, manager->action_what, manager->action_unit, &error);
        if (r < 0) {
                log_warning("Failed to send delayed message: %s", bus_error(&error, r));
                dbus_error_free(&error);

                manager->action_unit = NULL;
                manager->action_what = 0;
                return r;
        }

        return 1;
}

int manager_start_scope(
                Manager *manager,
                const char *scope,
                pid_t pid,
                const char *slice,
                const char *description,
                const char *after,
                const char *kill_mode,
                DBusError *error,
                char **job) {

        const char *timeout_stop_property = "TimeoutStopUSec", *send_sighup_property = "SendSIGHUP", *pids_property = "PIDs";
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub, sub2, sub3, sub4;
        uint64_t timeout = 500 * USEC_PER_MSEC;
        dbus_bool_t send_sighup = true;
        const char *fail = "fail";
        uint32_t u;

        assert(manager);
        assert(scope);
        assert(pid > 1);

        if (!slice)
                slice = "";

        m = dbus_message_new_method_call(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &scope) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &fail) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &sub))
                return log_oom();

        if (!isempty(slice)) {
                const char *slice_property = "Slice";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &slice_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
                    !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &slice) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        if (!isempty(description)) {
                const char *description_property = "Description";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &description_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
                    !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &description) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        if (!isempty(after)) {
                const char *after_property = "After";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &after_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "as", &sub3) ||
                    !dbus_message_iter_open_container(&sub3, DBUS_TYPE_ARRAY, "s", &sub4) ||
                    !dbus_message_iter_append_basic(&sub4, DBUS_TYPE_STRING, &after) ||
                    !dbus_message_iter_close_container(&sub3, &sub4) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        if (!isempty(kill_mode)) {
                const char *kill_mode_property = "KillMode";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &kill_mode_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
                    !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &kill_mode) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        /* cgroup empty notification is not available in containers
         * currently. To make this less problematic, let's shorten the
         * stop timeout for sessions, so that we don't wait
         * forever. */

        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &timeout_stop_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "t", &sub3) ||
            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_UINT64, &timeout) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&sub, &sub2))
                return log_oom();

        /* Make sure that the session shells are terminated with
         * SIGHUP since bash and friends tend to ignore SIGTERM */
        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &send_sighup_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "b", &sub3) ||
            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_BOOLEAN, &send_sighup) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&sub, &sub2))
                return log_oom();

        u = pid;
        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &pids_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "au", &sub3) ||
            !dbus_message_iter_open_container(&sub3, DBUS_TYPE_ARRAY, "u", &sub4) ||
            !dbus_message_iter_append_basic(&sub4, DBUS_TYPE_UINT32, &u) ||
            !dbus_message_iter_close_container(&sub3, &sub4) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&sub, &sub2))
                return log_oom();

        if (!dbus_message_iter_close_container(&iter, &sub))
                return log_oom();

        reply = dbus_connection_send_with_reply_and_block(manager->bus, m, -1, error);
        if (!reply)
                return -EIO;

        if (job) {
                const char *j;
                char *copy;

                if (!dbus_message_get_args(reply, error, DBUS_TYPE_OBJECT_PATH, &j, DBUS_TYPE_INVALID))
                        return -EIO;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 0;
}

int manager_start_unit(Manager *manager, const char *unit, DBusError *error, char **job) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *fail = "fail";
        int r;

        assert(manager);
        assert(unit);

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit,
                        DBUS_TYPE_STRING, &fail,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to start unit %s: %s", unit, bus_error(error, r));
                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                if (!dbus_message_get_args(reply, error,
                                           DBUS_TYPE_OBJECT_PATH, &j,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 0;
}

int manager_stop_unit(Manager *manager, const char *unit, DBusError *error, char **job) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *fail = "fail";
        int r;

        assert(manager);
        assert(unit);

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StopUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit,
                        DBUS_TYPE_STRING, &fail,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                if (dbus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    dbus_error_has_name(error, BUS_ERROR_LOAD_FAILED)) {

                        if (job)
                                *job = NULL;

                        dbus_error_free(error);
                        return 0;
                }

                log_error("Failed to stop unit %s: %s", unit, bus_error(error, r));
                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                if (!dbus_message_get_args(reply, error,
                                           DBUS_TYPE_OBJECT_PATH, &j,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, DBusError *error) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *w;
        int r;

        assert(manager);
        assert(unit);

        w = who == KILL_LEADER ? "process" : "cgroup";
        assert_cc(sizeof(signo) == sizeof(int32_t));

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit,
                        DBUS_TYPE_STRING, &w,
                        DBUS_TYPE_INT32, &signo,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to stop unit %s: %s", unit, bus_error(error, r));
                return r;
        }

        return 0;
}

int manager_unit_is_active(Manager *manager, const char *unit) {

        const char *interface = "org.freedesktop.systemd1.Unit";
        const char *property = "ActiveState";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *path = NULL;
        DBusMessageIter iter, sub;
        const char *state;
        DBusError error;
        int r;

        assert(manager);
        assert(unit);

        dbus_error_init(&error);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        &error,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &property,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                if (dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY) ||
                    dbus_error_has_name(&error, DBUS_ERROR_DISCONNECTED)) {
                        /* systemd might have droppped off
                         * momentarily, let's not make this an
                         * error */

                        dbus_error_free(&error);
                        return true;
                }

                if (dbus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ||
                    dbus_error_has_name(&error, BUS_ERROR_LOAD_FAILED)) {
                        /* If the unit is already unloaded then it's
                         * not active */

                        dbus_error_free(&error);
                        return false;
                }

                log_error("Failed to query ActiveState: %s", bus_error(&error, r));
                dbus_error_free(&error);
                return r;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_recurse(&iter, &sub);
        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_get_basic(&sub, &state);

        return !streq(state, "inactive") && !streq(state, "failed");
}
