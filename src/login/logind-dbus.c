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
#include <sys/capability.h>

#include "sd-id128.h"
#include "sd-messages.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "special.h"
#include "sleep-config.h"
#include "fileio-label.h"
#include "label.h"
#include "utf8.h"
#include "unit-name.h"
#include "virt.h"
#include "audit.h"
#include "bus-util.h"
#include "bus-error.h"
#include "logind.h"
#include "bus-errors.h"
#include "udev-util.h"

static int property_get_idle_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "b", manager_get_idle_hint(m, NULL) > 0);
}

static int property_get_idle_since_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        dual_timestamp t;

        assert(bus);
        assert(reply);
        assert(m);

        manager_get_idle_hint(m, &t);

        return sd_bus_message_append(reply, "t", streq(property, "IdleSinceHint") ? t.realtime : t.monotonic);
}

static int property_get_inhibited(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        InhibitWhat w;

        assert(bus);
        assert(reply);
        assert(m);

        w = manager_inhibit_what(m, streq(property, "BlockInhibited") ? INHIBIT_BLOCK : INHIBIT_DELAY);

        return sd_bus_message_append(reply, "s", inhibit_what_to_string(w));
}

static int property_get_preparing(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        bool b;

        assert(bus);
        assert(reply);
        assert(m);

        if (streq(property, "PreparingForShutdown"))
                b = !!(m->action_what & INHIBIT_SHUTDOWN);
        else
                b = !!(m->action_what & INHIBIT_SLEEP);

        return sd_bus_message_append(reply, "b", b);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_handle_action, handle_action, HandleAction);

static int method_get_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        const char *name;
        Session *session;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_session_by_pid(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Session *session = NULL;
        Manager *m = userdata;
        pid_t pid;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;

        if (pid == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        r = manager_get_session_by_pid(m, pid, &session);
        if (r < 0)
                return r;
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SESSION_FOR_PID, "PID "PID_FMT" does not belong to any known session", pid);

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        uint32_t uid;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER, "No user "UID_FMT" known or logged in", uid);

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user_by_pid(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        User *user = NULL;
        pid_t pid;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;

        if (pid == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        r = manager_get_user_by_pid(m, pid, &user);
        if (r < 0)
                return r;
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_USER_FOR_PID, "PID "PID_FMT" does not belong to any known or logged in user", pid);

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_seat(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        const char *name;
        Seat *seat;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        seat = hashmap_get(m->seats, name);
        if (!seat)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", name);

        p = seat_bus_path(seat);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_sessions(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Session *session;
        Iterator i;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(susso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(session, m->sessions, i) {
                _cleanup_free_ char *p = NULL;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(susso)",
                                          session->id,
                                          (uint32_t) session->user->uid,
                                          session->user->name,
                                          session->seat ? session->seat->id : "",
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int method_list_users(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        User *user;
        Iterator i;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(uso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(user, m->users, i) {
                _cleanup_free_ char *p = NULL;

                p = user_bus_path(user);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(uso)",
                                          (uint32_t) user->uid,
                                          user->name,
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int method_list_seats(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Seat *seat;
        Iterator i;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(so)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(seat, m->seats, i) {
                _cleanup_free_ char *p = NULL;

                p = seat_bus_path(seat);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(so)", seat->id, p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int method_list_inhibitors(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Inhibitor *inhibitor;
        Iterator i;
        int r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssuu)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(inhibitor, m->inhibitors, i) {

                r = sd_bus_message_append(reply, "(ssssuu)",
                                          strempty(inhibit_what_to_string(inhibitor->what)),
                                          strempty(inhibitor->who),
                                          strempty(inhibitor->why),
                                          strempty(inhibit_mode_to_string(inhibitor->mode)),
                                          (uint32_t) inhibitor->uid,
                                          (uint32_t) inhibitor->pid);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int method_create_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *service, *type, *class, *cseat, *tty, *display, *remote_user, *remote_host, *desktop;
        uint32_t uid, leader, audit_id = 0;
        _cleanup_free_ char *id = NULL;
        Session *session = NULL;
        Manager *m = userdata;
        User *user = NULL;
        Seat *seat = NULL;
        int remote;
        uint32_t vtnr = 0;
        SessionType t;
        SessionClass c;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "uusssssussbss", &uid, &leader, &service, &type, &class, &desktop, &cseat, &vtnr, &tty, &display, &remote, &remote_user, &remote_host);
        if (r < 0)
                return r;

        if (leader == 1)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid leader PID");

        if (isempty(type))
                t = _SESSION_TYPE_INVALID;
        else {
                t = session_type_from_string(type);
                if (t < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid session type %s", type);
        }

        if (isempty(class))
                c = _SESSION_CLASS_INVALID;
        else {
                c = session_class_from_string(class);
                if (c < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid session class %s", class);
        }

        if (isempty(desktop))
                desktop = NULL;
        else {
                if (!string_is_safe(desktop))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid desktop string %s", desktop);
        }

        if (isempty(cseat))
                seat = NULL;
        else {
                seat = hashmap_get(m->seats, cseat);
                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", cseat);
        }

        if (tty_is_vc(tty)) {
                int v;

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "TTY %s is virtual console but seat %s is not seat0", tty, seat->id);

                v = vtnr_from_tty(tty);
                if (v <= 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot determine VT number from virtual console TTY %s", tty);

                if (!vtnr)
                        vtnr = (uint32_t) v;
                else if (vtnr != (uint32_t) v)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified TTY and VT number do not match");

        } else if (tty_is_console(tty)) {

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Console TTY specified but seat is not seat0");

                if (vtnr != 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Console TTY specified but VT number is not 0");
        }

        if (seat) {
                if (seat_has_vts(seat)) {
                        if (!vtnr || vtnr > 63)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "VT number out of range");
                } else {
                        if (vtnr != 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Seat has no VTs but VT number not 0");
                }
        }

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                return r;

        if (t == _SESSION_TYPE_INVALID) {
                if (!isempty(display))
                        t = SESSION_X11;
                else if (!isempty(tty))
                        t = SESSION_TTY;
                else
                        t = SESSION_UNSPECIFIED;
        }

        if (c == _SESSION_CLASS_INVALID) {
                if (t == SESSION_UNSPECIFIED)
                        c = SESSION_BACKGROUND;
                else
                        c = SESSION_USER;
        }

        if (leader <= 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                assert_cc(sizeof(uint32_t) == sizeof(pid_t));

                r = sd_bus_creds_get_pid(creds, (pid_t*) &leader);
                if (r < 0)
                        return r;
        }

        manager_get_session_by_pid(m, leader, &session);
        if (session) {
                _cleanup_free_ char *path = NULL;
                _cleanup_close_ int fifo_fd = -1;

                /* Session already exists, client is probably
                 * something like "su" which changes uid but is still
                 * the same session */

                fifo_fd = session_create_fifo(session);
                if (fifo_fd < 0)
                        return fifo_fd;

                path = session_bus_path(session);
                if (!path)
                        return -ENOMEM;

                log_debug("Sending reply about an existing session: "
                          "id=%s object_path=%s uid=%u runtime_path=%s "
                          "session_fd=%d seat=%s vtnr=%u",
                          session->id,
                          path,
                          (uint32_t) session->user->uid,
                          session->user->runtime_path,
                          fifo_fd,
                          session->seat ? session->seat->id : "",
                          (uint32_t) session->vtnr);

                return sd_bus_reply_method_return(
                                message, "soshusub",
                                session->id,
                                path,
                                session->user->runtime_path,
                                fifo_fd,
                                (uint32_t) session->user->uid,
                                session->seat ? session->seat->id : "",
                                (uint32_t) session->vtnr,
                                true);
        }

        audit_session_from_pid(leader, &audit_id);
        if (audit_id > 0) {
                /* Keep our session IDs and the audit session IDs in sync */

                if (asprintf(&id, "%"PRIu32, audit_id) < 0)
                        return -ENOMEM;

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

                        if (asprintf(&id, "c%lu", ++m->session_counter) < 0)
                                return -ENOMEM;

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

        if (!isempty(desktop)) {
                session->desktop = strdup(desktop);
                if (!session->desktop) {
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

        session->create_message = sd_bus_message_ref(message);

        /* Now, let's wait until the slice unit and stuff got
         * created. We send the reply back from
         * session_send_create_reply().*/

        return 1;

fail:
        if (session)
                session_add_to_gc_queue(session);

        if (user)
                user_add_to_gc_queue(user);

        return r;
}

static int method_release_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        session_release(session);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session_on_seat(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *session_name, *seat_name;
        Manager *m = userdata;
        Session *session;
        Seat *seat;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        /* Same as ActivateSession() but refuses to work if
         * the seat doesn't match */

        r = sd_bus_message_read(message, "ss", &session_name, &seat_name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, session_name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", session_name);

        seat = hashmap_get(m->seats, seat_name);
        if (!seat)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", seat_name);

        if (session->seat != seat)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_NOT_ON_SEAT, "Session %s not on seat %s", session_name, seat_name);

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lock_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        r = session_send_lock(session, streq(sd_bus_message_get_member(message), "LockSession"));
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lock_sessions(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = session_send_lock_all(m, streq(sd_bus_message_get_member(message), "LockSessions"));
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kill_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *swho;
        Manager *m = userdata;
        Session *session;
        int32_t signo;
        KillWho who;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ssi", &name, &swho, &signo);
        if (r < 0)
                return r;

        if (isempty(swho))
                who = KILL_ALL;
        else {
                who = kill_who_from_string(swho);
                if (who < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid kill parameter '%s'", swho);
        }

        if (signo <= 0 || signo >= _NSIG)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        r = session_kill(session, who, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kill_user(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t uid;
        int32_t signo;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ui", &uid, &signo);
        if (r < 0)
                return r;

        if (signo <= 0 || signo >= _NSIG)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER, "No user "UID_FMT" known or logged in", uid);

        r = user_kill(user, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_terminate_session(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Session *session;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        r = session_stop(session, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_terminate_user(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t uid;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        user = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER, "No user "UID_FMT" known or logged in", uid);

        r = user_stop(user, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_terminate_seat(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Seat *seat;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        seat = hashmap_get(m->seats, name);
        if (!seat)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", name);

        r = seat_stop_sessions(seat, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_user_linger(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *cc = NULL;
        Manager *m = userdata;
        int b, r;
        struct passwd *pw;
        const char *path;
        uint32_t uid;
        int interactive;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ubb", &uid, &b, &interactive);
        if (r < 0)
                return r;

        errno = 0;
        pw = getpwuid(uid);
        if (!pw)
                return errno ? -errno : -ENOENT;

        r = bus_verify_polkit_async(bus,
                                    &m->polkit_registry,
                                    message,
                                    "org.freedesktop.login1.set-user-linger",
                                    interactive,
                                    error,
                                    method_set_user_linger, m);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        mkdir_p_label("/var/lib/systemd", 0755);

        r = mkdir_safe_label("/var/lib/systemd/linger", 0755, 0, 0);
        if (r < 0)
                return r;

        cc = cescape(pw->pw_name);
        if (!cc)
                return -ENOMEM;

        path = strappenda("/var/lib/systemd/linger/", cc);
        if (b) {
                User *u;

                r = touch(path);
                if (r < 0)
                        return r;

                if (manager_add_user_by_uid(m, uid, &u) >= 0)
                        user_start(u);

        } else {
                User *u;

                r = unlink(path);
                if (r < 0 && errno != ENOENT)
                        return -errno;

                u = hashmap_get(m->users, ULONG_TO_PTR((unsigned long) uid));
                if (u)
                        user_add_to_gc_queue(u);
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int trigger_device(Manager *m, struct udev_device *d) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *first, *item;
        int r;

        assert(m);

        e = udev_enumerate_new(m->udev);
        if (!e)
                return -ENOMEM;

        if (d) {
                r = udev_enumerate_add_match_parent(e, d);
                if (r < 0)
                        return r;
        }

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                return r;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_free_ char *t = NULL;
                const char *p;

                p = udev_list_entry_get_name(item);

                t = strappend(p, "/uevent");
                if (!t)
                        return -ENOMEM;

                write_string_file(t, "change");
        }

        return 0;
}

static int attach_device(Manager *m, const char *seat, const char *sysfs) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_free_ char *rule = NULL, *file = NULL;
        const char *id_for_seat;
        int r;

        assert(m);
        assert(seat);
        assert(sysfs);

        d = udev_device_new_from_syspath(m->udev, sysfs);
        if (!d)
                return -ENODEV;

        if (!udev_device_has_tag(d, "seat"))
                return -ENODEV;

        id_for_seat = udev_device_get_property_value(d, "ID_FOR_SEAT");
        if (!id_for_seat)
                return -ENODEV;

        if (asprintf(&file, "/etc/udev/rules.d/72-seat-%s.rules", id_for_seat) < 0)
                return -ENOMEM;

        if (asprintf(&rule, "TAG==\"seat\", ENV{ID_FOR_SEAT}==\"%s\", ENV{ID_SEAT}=\"%s\"", id_for_seat, seat) < 0)
                return -ENOMEM;

        mkdir_p_label("/etc/udev/rules.d", 0755);
        label_init("/etc");
        r = write_string_file_atomic_label(file, rule);
        if (r < 0)
                return r;

        return trigger_device(m, d);
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

static int method_attach_device(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *sysfs, *seat;
        Manager *m = userdata;
        int interactive, r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ssb", &seat, &sysfs, &interactive);
        if (r < 0)
                return r;

        if (!path_startswith(sysfs, "/sys"))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not in /sys", sysfs);

        if (!seat_name_is_valid(seat))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Seat %s is not valid", seat);

        r = bus_verify_polkit_async(bus,
                                    &m->polkit_registry,
                                    message,
                                    "org.freedesktop.login1.attach-device",
                                    interactive,
                                    error,
                                    method_attach_device, m);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = attach_device(m, seat, sysfs);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_flush_devices(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int interactive, r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &interactive);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(bus,
                                    &m->polkit_registry,
                                    message,
                                    "org.freedesktop.login1.flush-devices",
                                    interactive,
                                    error,
                                    method_flush_devices, m);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = flush_devices(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
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

static int lid_switch_ignore_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = userdata;

        assert(e);
        assert(m);

        m->lid_switch_ignore_event_source = sd_event_source_unref(m->lid_switch_ignore_event_source);
        return 0;
}

int manager_set_lid_switch_ignore(Manager *m, usec_t until) {
        int r;

        assert(m);

        if (until <= now(CLOCK_MONOTONIC))
                return 0;

        /* We want to ignore the lid switch for a while after each
         * suspend, and after boot-up. Hence let's install a timer for
         * this. As long as the event source exists we ignore the lid
         * switch. */

        if (m->lid_switch_ignore_event_source) {
                usec_t u;

                r = sd_event_source_get_time(m->lid_switch_ignore_event_source, &u);
                if (r < 0)
                        return r;

                if (until <= u)
                        return 0;

                r = sd_event_source_set_time(m->lid_switch_ignore_event_source, until);
        } else
                r = sd_event_add_time(
                                m->event,
                                &m->lid_switch_ignore_event_source,
                                CLOCK_MONOTONIC,
                                until, 0,
                                lid_switch_ignore_handler, m);

        return r;
}

static int execute_shutdown_or_sleep(
                Manager *m,
                InhibitWhat w,
                const char *unit_name,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *p;
        char *c;
        int r;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(unit_name);

        bus_manager_log_shutdown(m, w, unit_name);

        r = sd_bus_call_method(
                        m->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        error,
                        &reply,
                        "ss", unit_name, "replace-irreversibly");
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "o", &p);
        if (r < 0)
                return r;

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        m->action_unit = unit_name;
        free(m->action_job);
        m->action_job = c;
        m->action_what = w;

        /* Make sure the lid switch is ignored for a while */
        manager_set_lid_switch_ignore(m, now(CLOCK_MONOTONIC) + IGNORE_LID_SWITCH_SUSPEND_USEC);

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

static int send_prepare_for(Manager *m, InhibitWhat w, bool _active) {

        static const char * const signal_name[_INHIBIT_WHAT_MAX] = {
                [INHIBIT_SHUTDOWN] = "PrepareForShutdown",
                [INHIBIT_SLEEP] = "PrepareForSleep"
        };

        int active = _active;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(signal_name[w]);

        return sd_bus_emit_signal(m->bus,
                                  "/org/freedesktop/login1",
                                  "org.freedesktop.login1.Manager",
                                  signal_name[w],
                                  "b",
                                  active);
}

int bus_manager_shutdown_or_sleep_now_or_later(
                Manager *m,
                const char *unit_name,
                InhibitWhat w,
                sd_bus_error *error) {

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
                manager_is_inhibited(m, w, INHIBIT_DELAY, NULL, false, false, 0, NULL);

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

static int method_do_shutdown_or_sleep(
                Manager *m,
                sd_bus_message *message,
                const char *unit_name,
                InhibitWhat w,
                const char *action,
                const char *action_multiple_sessions,
                const char *action_ignore_inhibit,
                const char *sleep_verb,
                sd_bus_message_handler_t method,
                sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        bool multiple_sessions, blocked;
        int interactive, r;
        uid_t uid;

        assert(m);
        assert(message);
        assert(unit_name);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);
        assert(action);
        assert(action_multiple_sessions);
        assert(action_ignore_inhibit);
        assert(method);

        r = sd_bus_message_read(message, "b", &interactive);
        if (r < 0)
                return r;

        /* Don't allow multiple jobs being executed at the same time */
        if (m->action_what)
                return sd_bus_error_setf(error, BUS_ERROR_OPERATION_IN_PROGRESS, "There's already a shutdown or sleep operation in progress");

        if (sleep_verb) {
                r = can_sleep(sleep_verb);
                if (r < 0)
                        return r;

                if (r == 0)
                        return sd_bus_error_setf(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED, "Sleep verb not supported");
        }

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_UID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, uid, NULL);

        if (multiple_sessions) {
                r = bus_verify_polkit_async(m->bus, &m->polkit_registry, message,
                                            action_multiple_sessions, interactive, error, method, m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (blocked) {
                r = bus_verify_polkit_async(m->bus, &m->polkit_registry, message,
                                            action_ignore_inhibit, interactive, error, method, m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (!multiple_sessions && !blocked) {
                r = bus_verify_polkit_async(m->bus, &m->polkit_registry, message,
                                            action, interactive, error, method, m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        r = bus_manager_shutdown_or_sleep_now_or_later(m, unit_name, w, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_POWEROFF_TARGET,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.power-off",
                        "org.freedesktop.login1.power-off-multiple-sessions",
                        "org.freedesktop.login1.power-off-ignore-inhibit",
                        NULL,
                        method_poweroff,
                        error);
}

static int method_reboot(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_REBOOT_TARGET,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.reboot",
                        "org.freedesktop.login1.reboot-multiple-sessions",
                        "org.freedesktop.login1.reboot-ignore-inhibit",
                        NULL,
                        method_reboot,
                        error);
}

static int method_suspend(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_SUSPEND_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.suspend",
                        "org.freedesktop.login1.suspend-multiple-sessions",
                        "org.freedesktop.login1.suspend-ignore-inhibit",
                        "suspend",
                        method_suspend,
                        error);
}

static int method_hibernate(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_HIBERNATE_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hibernate",
                        method_hibernate,
                        error);
}

static int method_hybrid_sleep(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_HYBRID_SLEEP_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hybrid-sleep",
                        method_hybrid_sleep,
                        error);
}

static int method_can_shutdown_or_sleep(
                Manager *m,
                sd_bus_message *message,
                InhibitWhat w,
                const char *action,
                const char *action_multiple_sessions,
                const char *action_ignore_inhibit,
                const char *sleep_verb,
                sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        bool multiple_sessions, challenge, blocked;
        const char *result = NULL;
        uid_t uid;
        int r;

        assert(m);
        assert(message);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);
        assert(action);
        assert(action_multiple_sessions);
        assert(action_ignore_inhibit);

        if (sleep_verb) {
                r = can_sleep(sleep_verb);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_reply_method_return(message, "s", "na");
        }

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_UID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, uid, NULL);

        if (multiple_sessions) {
                r = bus_verify_polkit(m->bus, message, action_multiple_sessions, false, &challenge, error);
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
                r = bus_verify_polkit(m->bus, message, action_ignore_inhibit, false, &challenge, error);
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

                r = bus_verify_polkit(m->bus, message, action, false, &challenge, error);
                if (r < 0)
                        return r;

                if (r > 0)
                        result = "yes";
                else if (challenge)
                        result = "challenge";
                else
                        result = "no";
        }

        return sd_bus_reply_method_return(message, "s", result);
}

static int method_can_poweroff(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(
                        m, message,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.power-off",
                        "org.freedesktop.login1.power-off-multiple-sessions",
                        "org.freedesktop.login1.power-off-ignore-inhibit",
                        NULL,
                        error);
}

static int method_can_reboot(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(
                        m, message,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.reboot",
                        "org.freedesktop.login1.reboot-multiple-sessions",
                        "org.freedesktop.login1.reboot-ignore-inhibit",
                        NULL,
                        error);
}

static int method_can_suspend(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(
                        m, message,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.suspend",
                        "org.freedesktop.login1.suspend-multiple-sessions",
                        "org.freedesktop.login1.suspend-ignore-inhibit",
                        "suspend",
                        error);
}

static int method_can_hibernate(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(
                        m, message,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hibernate",
                        error);
}

static int method_can_hybrid_sleep(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(
                        m, message,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hybrid-sleep",
                        error);
}

static int method_inhibit(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        const char *who, *why, *what, *mode;
        _cleanup_free_ char *id = NULL;
        _cleanup_close_ int fifo_fd = -1;
        Manager *m = userdata;
        Inhibitor *i = NULL;
        InhibitMode mm;
        InhibitWhat w;
        pid_t pid;
        uid_t uid;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ssss", &what, &who, &why, &mode);
        if (r < 0)
                return r;

        w = inhibit_what_from_string(what);
        if (w <= 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid what specification %s", what);

        mm = inhibit_mode_from_string(mode);
        if (mm < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid mode specification %s", mode);

        /* Delay is only supported for shutdown/sleep */
        if (mm == INHIBIT_DELAY && (w & ~(INHIBIT_SHUTDOWN|INHIBIT_SLEEP)))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Delay inhibitors only supported for shutdown and sleep");

        /* Don't allow taking delay locks while we are already
         * executing the operation. We shouldn't create the impression
         * that the lock was successful if the machine is about to go
         * down/suspend any moment. */
        if (m->action_what & w)
                return sd_bus_error_setf(error, BUS_ERROR_OPERATION_IN_PROGRESS, "The operation inhibition has been requested for is already running");

        r = bus_verify_polkit_async(bus, &m->polkit_registry, message,
                                    w == INHIBIT_SHUTDOWN             ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-shutdown" : "org.freedesktop.login1.inhibit-delay-shutdown") :
                                    w == INHIBIT_SLEEP                ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-sleep"    : "org.freedesktop.login1.inhibit-delay-sleep") :
                                    w == INHIBIT_IDLE                 ? "org.freedesktop.login1.inhibit-block-idle" :
                                    w == INHIBIT_HANDLE_POWER_KEY     ? "org.freedesktop.login1.inhibit-handle-power-key" :
                                    w == INHIBIT_HANDLE_SUSPEND_KEY   ? "org.freedesktop.login1.inhibit-handle-suspend-key" :
                                    w == INHIBIT_HANDLE_HIBERNATE_KEY ? "org.freedesktop.login1.inhibit-handle-hibernate-key" :
                                                                        "org.freedesktop.login1.inhibit-handle-lid-switch",
                                    false, error, method_inhibit, m);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pid(creds, &pid);
        if (r < 0)
                return r;

        do {
                free(id);
                id = NULL;

                if (asprintf(&id, "%lu", ++m->inhibit_counter) < 0)
                        return -ENOMEM;

        } while (hashmap_get(m->inhibitors, id));

        r = manager_add_inhibitor(m, id, &i);
        if (r < 0)
                return r;

        i->what = w;
        i->mode = mm;
        i->pid = pid;
        i->uid = uid;
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

        inhibitor_start(i);

        return sd_bus_reply_method_return(message, "h", fifo_fd);

fail:
        if (i)
                inhibitor_free(i);

        return r;
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("NAutoVTs", "u", NULL, offsetof(Manager, n_autovts), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillOnlyUsers", "as", NULL, offsetof(Manager, kill_only_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillExcludeUsers", "as", NULL, offsetof(Manager, kill_exclude_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillUserProcesses", "b", NULL, offsetof(Manager, kill_user_processes), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BlockInhibited", "s", property_get_inhibited, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DelayInhibited", "s", property_get_inhibited, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("InhibitDelayMaxUSec", "t", NULL, offsetof(Manager, inhibit_delay_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandlePowerKey", "s", property_get_handle_action, offsetof(Manager, handle_power_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleSuspendKey", "s", property_get_handle_action, offsetof(Manager, handle_suspend_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleHibernateKey", "s", property_get_handle_action, offsetof(Manager, handle_hibernate_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleLidSwitch", "s", property_get_handle_action, offsetof(Manager, handle_lid_switch), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleAction", "s", property_get_handle_action, offsetof(Manager, idle_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleActionUSec", "t", NULL, offsetof(Manager, idle_action_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PreparingForShutdown", "b", property_get_preparing, 0, 0),
        SD_BUS_PROPERTY("PreparingForSleep", "b", property_get_preparing, 0, 0),

        SD_BUS_METHOD("GetSession", "s", "o", method_get_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetSessionByPID", "u", "o", method_get_session_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUser", "u", "o", method_get_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUserByPID", "u", "o", method_get_user_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetSeat", "s", "o", method_get_seat, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListSessions", NULL, "a(susso)", method_list_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUsers", NULL, "a(uso)", method_list_users, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListSeats", NULL, "a(so)", method_list_seats, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListInhibitors", NULL, "a(ssssuu)", method_list_inhibitors, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateSession", "uusssssussbssa(sv)", "soshusub", method_create_session, 0),
        SD_BUS_METHOD("ReleaseSession", "s", NULL, method_release_session, 0),
        SD_BUS_METHOD("ActivateSession", "s", NULL, method_activate_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ActivateSessionOnSeat", "ss", NULL, method_activate_session_on_seat, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LockSession", "s", NULL, method_lock_session, 0),
        SD_BUS_METHOD("UnlockSession", "s", NULL, method_lock_session, 0),
        SD_BUS_METHOD("LockSessions", NULL, NULL, method_lock_sessions, 0),
        SD_BUS_METHOD("UnlockSessions", NULL, NULL, method_lock_sessions, 0),
        SD_BUS_METHOD("KillSession", "ssi", NULL, method_kill_session, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("KillUser", "ui", NULL, method_kill_user, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("TerminateSession", "s", NULL, method_terminate_session, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("TerminateUser", "u", NULL, method_terminate_user, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("TerminateSeat", "s", NULL, method_terminate_seat, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("SetUserLinger", "ubb", NULL, method_set_user_linger, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("AttachDevice", "ssb", NULL, method_attach_device, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("FlushDevices", "b", NULL, method_flush_devices, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PowerOff", "b", NULL, method_poweroff, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reboot", "b", NULL, method_reboot, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Suspend", "b", NULL, method_suspend, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Hibernate", "b", NULL, method_hibernate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("HybridSleep", "b", NULL, method_hybrid_sleep, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanPowerOff", NULL, "s", method_can_poweroff, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanReboot", NULL, "s", method_can_reboot, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanSuspend", NULL, "s", method_can_suspend, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanHibernate", NULL, "s", method_can_hibernate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanHybridSleep", NULL, "s", method_can_hybrid_sleep, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Inhibit", "ssss", "h", method_inhibit, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL("SessionNew", "so", 0),
        SD_BUS_SIGNAL("SessionRemoved", "so", 0),
        SD_BUS_SIGNAL("UserNew", "uo", 0),
        SD_BUS_SIGNAL("UserRemoved", "uo", 0),
        SD_BUS_SIGNAL("SeatNew", "so", 0),
        SD_BUS_SIGNAL("SeatRemoved", "so", 0),
        SD_BUS_SIGNAL("PrepareForShutdown", "b", 0),
        SD_BUS_SIGNAL("PrepareForSleep", "b", 0),

        SD_BUS_VTABLE_END
};

static int session_jobs_reply(Session *s, const char *unit, const char *result) {
        int r = 0;

        assert(s);
        assert(unit);

        if (!s->started)
                return r;

        if (streq(result, "done"))
                r = session_send_create_reply(s, NULL);
        else {
                _cleanup_bus_error_free_ sd_bus_error e = SD_BUS_ERROR_NULL;

                sd_bus_error_setf(&e, BUS_ERROR_JOB_FAILED, "Start job for unit %s failed with '%s'", unit, result);
                r = session_send_create_reply(s, &e);
        }

        return r;
}

int match_job_removed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *result, *unit;
        Manager *m = userdata;
        Session *session;
        uint32_t id;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        if (m->action_job && streq(m->action_job, path)) {
                log_info("Operation finished.");

                /* Tell people that they now may take a lock again */
                send_prepare_for(m, m->action_what, false);

                free(m->action_job);
                m->action_job = NULL;
                m->action_unit = NULL;
                m->action_what = 0;
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session) {

                if (streq_ptr(path, session->scope_job)) {
                        free(session->scope_job);
                        session->scope_job = NULL;
                }

                session_jobs_reply(session, unit, result);

                session_save(session);
                session_add_to_gc_queue(session);
        }

        user = hashmap_get(m->user_units, unit);
        if (user) {

                if (streq_ptr(path, user->service_job)) {
                        free(user->service_job);
                        user->service_job = NULL;
                }

                if (streq_ptr(path, user->slice_job)) {
                        free(user->slice_job);
                        user->slice_job = NULL;
                }

                LIST_FOREACH(sessions_by_user, session, user->sessions) {
                        session_jobs_reply(session, unit, result);
                }

                user_save(user);
                user_add_to_gc_queue(user);
        }

        return 0;
}

int match_unit_removed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = userdata;
        Session *session;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_properties_changed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *unit = NULL;
        Manager *m = userdata;
        const char *path;
        Session *session;
        User *user;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r < 0)
                /* quietly ignore non-units paths */
                return r == -EINVAL ? 0 : r;

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_reloading(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        Iterator i;
        int b, r;

        assert(bus);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our sessions */
        log_debug("System manager has been reloaded, rechecking sessions...");

        HASHMAP_FOREACH(session, m->sessions, i)
                session_add_to_gc_queue(session);

        return 0;
}

int match_name_owner_changed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *old, *new;
        Manager *m = userdata;
        Session *session;
        Iterator i;
        int r;


        char *key;

        r = sd_bus_message_read(message, "sss", &name, &old, &new);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        if (isempty(old) || !isempty(new))
                return 0;

        key = set_remove(m->busnames, (char*) old);
        if (!key)
                return 0;

        /* Drop all controllers owned by this name */

        free(key);

        HASHMAP_FOREACH(session, m->sessions, i)
                if (session_is_controller(session, old))
                        session_drop_controller(session);

        return 0;
}

int manager_send_changed(Manager *manager, const char *property, ...) {
        char **l;

        assert(manager);

        l = strv_from_stdarg_alloca(property);

        return sd_bus_emit_properties_changed_strv(
                        manager->bus,
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        l);
}

int manager_dispatch_delayed(Manager *manager) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        Inhibitor *offending = NULL;
        int r;

        assert(manager);

        if (manager->action_what == 0 || manager->action_job)
                return 0;

        /* Continue delay? */
        if (manager_is_inhibited(manager, manager->action_what, INHIBIT_DELAY, NULL, false, false, 0, &offending)) {
                _cleanup_free_ char *comm = NULL, *u = NULL;

                get_process_comm(offending->pid, &comm);
                u = uid_to_name(offending->uid);

                if (manager->action_timestamp + manager->inhibit_delay_max > now(CLOCK_MONOTONIC))
                        return 0;

                log_info("Delay lock is active (UID "UID_FMT"/%s, PID "PID_FMT"/%s) but inhibitor timeout is reached.",
                         offending->uid, strna(u),
                         offending->pid, strna(comm));
        }

        /* Actually do the operation */
        r = execute_shutdown_or_sleep(manager, manager->action_what, manager->action_unit, &error);
        if (r < 0) {
                log_warning("Failed to send delayed message: %s", bus_error_message(&error, r));

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
                const char *after, const char *after2,
                sd_bus_error *error,
                char **job) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        int r;

        assert(manager);
        assert(scope);
        assert(pid > 1);

        r = sd_bus_message_new_method_call(
                        manager->bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", strempty(scope), "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        if (!isempty(slice)) {
                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        if (!isempty(description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", description);
                if (r < 0)
                        return r;
        }

        if (!isempty(after)) {
                r = sd_bus_message_append(m, "(sv)", "After", "as", 1, after);
                if (r < 0)
                        return r;
        }

        if (!isempty(after2)) {
                r = sd_bus_message_append(m, "(sv)", "After", "as", 1, after2);
                if (r < 0)
                        return r;
        }

        /* cgroup empty notification is not available in containers
         * currently. To make this less problematic, let's shorten the
         * stop timeout for sessions, so that we don't wait
         * forever. */

        /* Make sure that the session shells are terminated with
         * SIGHUP since bash and friends tend to ignore SIGTERM */
        r = sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", true);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, pid);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(manager->bus, m, 0, error, &reply);
        if (r < 0)
                return r;

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_start_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        error,
                        &reply,
                        "ss", unit, "fail");
        if (r < 0)
                return r;

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StopUnit",
                        error,
                        &reply,
                        "ss", unit, "fail");
        if (r < 0) {
                if (sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(error, BUS_ERROR_LOAD_FAILED)) {

                        if (job)
                                *job = NULL;

                        sd_bus_error_free(error);
                        return 0;
                }

                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_abandon_scope(Manager *manager, const char *scope, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(manager);
        assert(scope);

        path = unit_dbus_path_from_name(scope);
        if (!path)
                return -ENOMEM;

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Scope",
                        "Abandon",
                        error,
                        NULL,
                        NULL);
        if (r < 0) {
                if (sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(error, BUS_ERROR_LOAD_FAILED) ||
                    sd_bus_error_has_name(error, BUS_ERROR_SCOPE_NOT_RUNNING)) {
                        sd_bus_error_free(error);
                        return 0;
                }

                return r;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, sd_bus_error *error) {
        assert(manager);
        assert(unit);

        return sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        error,
                        NULL,
                        "ssi", unit, who == KILL_LEADER ? "main" : "all", signo);
}

int manager_unit_is_active(Manager *manager, const char *unit) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        const char *state;
        int r;

        assert(manager);
        assert(unit);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                /* systemd might have droppped off momentarily, let's
                 * not make this an error */
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                /* If the unit is already unloaded then it's not
                 * active */
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(&error, BUS_ERROR_LOAD_FAILED))
                        return false;

                return r;
        }

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return -EINVAL;

        return !streq(state, "inactive") && !streq(state, "failed");
}

int manager_job_is_active(Manager *manager, const char *path) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(path);

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Job",
                        "State",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        return false;

                return r;
        }

        /* We don't actually care about the state really. The fact
         * that we could read the job state is enough for us */

        return true;
}
