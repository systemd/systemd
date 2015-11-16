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
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "audit-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "formats-util.h"
#include "fs-util.h"
#include "logind.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "sleep-config.h"
#include "special.h"
#include "strv.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "unit-name.h"
#include "user-util.h"
#include "utmp-wtmp.h"

int manager_get_session_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Session **ret) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        Session *session;
        int r;

        assert(m);
        assert(message);
        assert(ret);

        if (isempty(name)) {
                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_SESSION|SD_BUS_CREDS_AUGMENT, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_session(creds, &name);
                if (r < 0)
                        return r;
        }

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        *ret = session;
        return 0;
}

int manager_get_user_from_creds(Manager *m, sd_bus_message *message, uid_t uid, sd_bus_error *error, User **ret) {
        User *user;
        int r;

        assert(m);
        assert(message);
        assert(ret);

        if (uid == UID_INVALID) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                /* Note that we get the owner UID of the session, not the actual client UID here! */
                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_owner_uid(creds, &uid);
                if (r < 0)
                        return r;
        }

        user = hashmap_get(m->users, UID_TO_PTR(uid));
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER, "No user "UID_FMT" known or logged in", uid);

        *ret = user;
        return 0;
}

int manager_get_seat_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Seat **ret) {
        Seat *seat;
        int r;

        assert(m);
        assert(message);
        assert(ret);

        if (isempty(name)) {
                Session *session;

                r = manager_get_session_from_creds(m, message, NULL, error, &session);
                if (r < 0)
                        return r;

                seat = session->seat;

                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "Session has no seat.");
        } else {
                seat = hashmap_get(m->seats, name);
                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", name);
        }

        *ret = seat;
        return 0;
}

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
        dual_timestamp t = DUAL_TIMESTAMP_NULL;

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

static int property_get_scheduled_shutdown(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(m);

        r = sd_bus_message_open_container(reply, 'r', "st");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "st", m->scheduled_shutdown_type, m->scheduled_shutdown_timeout);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_handle_action, handle_action, HandleAction);

static int property_get_docked(
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

        return sd_bus_message_append(reply, "b", manager_is_docked_or_external_displays(m));
}

static int method_get_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        const char *name;
        Session *session;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_session_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Session *session = NULL;
        Manager *m = userdata;
        pid_t pid;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return -EINVAL;

        if (pid == 0) {
                r = manager_get_session_from_creds(m, message, NULL, error, &session);
                if (r < 0)
                        return r;
        } else {
                r = manager_get_session_by_pid(m, pid, &session);
                if (r < 0)
                        return r;

                if (!session)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SESSION_FOR_PID, "PID "PID_FMT" does not belong to any known session", pid);
        }

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        uint32_t uid;
        User *user;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        User *user = NULL;
        pid_t pid;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return -EINVAL;

        if (pid == 0) {
                r = manager_get_user_from_creds(m, message, UID_INVALID, error, &user);
                if (r < 0)
                        return r;
        } else {
                r = manager_get_user_by_pid(m, pid, &user);
                if (r < 0)
                        return r;
                if (!user)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_USER_FOR_PID, "PID "PID_FMT" does not belong to any known or logged in user", pid);
        }

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        const char *name;
        Seat *seat;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, name, error, &seat);
        if (r < 0)
                return r;

        p = seat_bus_path(seat);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Session *session;
        Iterator i;
        int r;

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

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_users(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        User *user;
        Iterator i;
        int r;

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

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_seats(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Seat *seat;
        Iterator i;
        int r;

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

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_inhibitors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Inhibitor *inhibitor;
        Iterator i;
        int r;

        assert(message);
        assert(m);

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

        return sd_bus_send(NULL, reply, NULL);
}

static int method_create_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *service, *type, *class, *cseat, *tty, *display, *remote_user, *remote_host, *desktop;
        uint32_t audit_id = 0;
        _cleanup_free_ char *id = NULL;
        Session *session = NULL;
        Manager *m = userdata;
        User *user = NULL;
        Seat *seat = NULL;
        pid_t leader;
        uid_t uid;
        int remote;
        uint32_t vtnr = 0;
        SessionType t;
        SessionClass c;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));
        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "uusssssussbss", &uid, &leader, &service, &type, &class, &desktop, &cseat, &vtnr, &tty, &display, &remote, &remote_user, &remote_host);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid UID");
        if (leader < 0 || leader == 1)
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

        if (leader == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, (pid_t*) &leader);
                if (r < 0)
                        return r;
        }

        r = manager_get_session_by_pid(m, leader, NULL);
        if (r > 0)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_BUSY, "Already running in a session");

        /*
         * Old gdm and lightdm start the user-session on the same VT as
         * the greeter session. But they destroy the greeter session
         * after the user-session and want the user-session to take
         * over the VT. We need to support this for
         * backwards-compatibility, so make sure we allow new sessions
         * on a VT that a greeter is running on. Furthermore, to allow
         * re-logins, we have to allow a greeter to take over a used VT for
         * the exact same reasons.
         */
        if (c != SESSION_GREETER &&
            vtnr > 0 &&
            vtnr < m->seat0->position_count &&
            m->seat0->positions[vtnr] &&
            m->seat0->positions[vtnr]->class != SESSION_GREETER)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_BUSY, "Already occupied by a session");

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

                        id = mfree(id);
                }
        }

        if (!id) {
                do {
                        id = mfree(id);

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
         * session_send_create_reply(). */

        return 1;

fail:
        if (session)
                session_add_to_gc_queue(session);

        if (user)
                user_add_to_gc_queue(user);

        return r;
}

static int method_release_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        r = session_release(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_activate(message, session, error);
}

static int method_activate_session_on_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *session_name, *seat_name;
        Manager *m = userdata;
        Session *session;
        Seat *seat;
        int r;

        assert(message);
        assert(m);

        /* Same as ActivateSession() but refuses to work if
         * the seat doesn't match */

        r = sd_bus_message_read(message, "ss", &session_name, &seat_name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, session_name, error, &session);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, seat_name, error, &seat);
        if (r < 0)
                return r;

        if (session->seat != seat)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_NOT_ON_SEAT, "Session %s not on seat %s", session_name, seat_name);

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lock_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_lock(message, session, error);
}

static int method_lock_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.login1.lock-sessions",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_send_lock_all(m, streq(sd_bus_message_get_member(message), "LockSessions"));
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kill_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name;
        Manager *m = userdata;
        Session *session;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_kill(message, session, error);
}

static int method_kill_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t uid;
        User *user;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        return bus_user_method_kill(message, user, error);
}

static int method_terminate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Session *session;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_terminate(message, session, error);
}

static int method_terminate_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t uid;
        User *user;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        return bus_user_method_terminate(message, user, error);
}

static int method_terminate_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Seat *seat;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, name, error, &seat);
        if (r < 0)
                return r;

        return bus_seat_method_terminate(message, seat, error);
}

static int method_set_user_linger(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *cc = NULL;
        Manager *m = userdata;
        int b, r;
        struct passwd *pw;
        const char *path;
        uint32_t uid;
        int interactive;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ubb", &uid, &b, &interactive);
        if (r < 0)
                return r;

        if (uid == UID_INVALID) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                /* Note that we get the owner UID of the session, not the actual client UID here! */
                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_owner_uid(creds, &uid);
                if (r < 0)
                        return r;

        } else if (!uid_is_valid(uid))
                return -EINVAL;

        errno = 0;
        pw = getpwuid(uid);
        if (!pw)
                return errno ? -errno : -ENOENT;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.login1.set-user-linger",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
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

        path = strjoina("/var/lib/systemd/linger/", cc);
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

                u = hashmap_get(m->users, UID_TO_PTR(uid));
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

                write_string_file(t, "change", WRITE_STRING_FILE_CREATE);
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
        mac_selinux_init("/etc");
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
                        log_warning_errno(errno, "Failed to open /etc/udev/rules.d: %m");
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
                                log_warning_errno(errno, "Failed to unlink %s: %m", de->d_name);
                }
        }

        return trigger_device(m, NULL);
}

static int method_attach_device(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *sysfs, *seat;
        Manager *m = userdata;
        int interactive, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ssb", &seat, &sysfs, &interactive);
        if (r < 0)
                return r;

        if (!path_startswith(sysfs, "/sys"))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not in /sys", sysfs);

        if (!seat_name_is_valid(seat))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Seat %s is not valid", seat);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.login1.attach-device",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = attach_device(m, seat, sysfs);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_flush_devices(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int interactive, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &interactive);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.login1.flush-devices",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
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
                p = "MESSAGE=System is powering down";
                q = "SHUTDOWN=power-off";
        } else if (streq(unit_name, SPECIAL_HALT_TARGET)) {
                p = "MESSAGE=System is halting";
                q = "SHUTDOWN=halt";
        } else if (streq(unit_name, SPECIAL_REBOOT_TARGET)) {
                p = "MESSAGE=System is rebooting";
                q = "SHUTDOWN=reboot";
        } else if (streq(unit_name, SPECIAL_KEXEC_TARGET)) {
                p = "MESSAGE=System is rebooting with kexec";
                q = "SHUTDOWN=kexec";
        } else {
                p = "MESSAGE=System is shutting down";
                q = NULL;
        }

        if (isempty(m->wall_message))
                p = strjoina(p, ".");
        else
                p = strjoina(p, " (", m->wall_message, ").");

        return log_struct(LOG_NOTICE,
                          LOG_MESSAGE_ID(SD_MESSAGE_SHUTDOWN),
                          p,
                          q,
                          NULL);
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

static void reset_scheduled_shutdown(Manager *m) {
        m->scheduled_shutdown_timeout_source = sd_event_source_unref(m->scheduled_shutdown_timeout_source);
        m->wall_message_timeout_source = sd_event_source_unref(m->wall_message_timeout_source);
        m->nologin_timeout_source = sd_event_source_unref(m->nologin_timeout_source);
        m->scheduled_shutdown_type = mfree(m->scheduled_shutdown_type);
        m->scheduled_shutdown_timeout = 0;
        m->shutdown_dry_run = false;

        if (m->unlink_nologin) {
                (void) unlink("/run/nologin");
                m->unlink_nologin = false;
        }
}

static int execute_shutdown_or_sleep(
                Manager *m,
                InhibitWhat w,
                const char *unit_name,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        char *c = NULL;
        const char *p;
        int r;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(unit_name);

        bus_manager_log_shutdown(m, w, unit_name);

        if (m->shutdown_dry_run) {
                log_info("Running in dry run, suppressing action.");
                reset_scheduled_shutdown(m);
        } else {
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
        }

        m->action_unit = unit_name;
        free(m->action_job);
        m->action_job = c;
        m->action_what = w;

        /* Make sure the lid switch is ignored for a while */
        manager_set_lid_switch_ignore(m, now(CLOCK_MONOTONIC) + m->holdoff_timeout_usec);

        return 0;
}

int manager_dispatch_delayed(Manager *manager, bool timeout) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        Inhibitor *offending = NULL;
        int r;

        assert(manager);

        if (manager->action_what == 0 || manager->action_job)
                return 0;

        if (manager_is_inhibited(manager, manager->action_what, INHIBIT_DELAY, NULL, false, false, 0, &offending)) {
                _cleanup_free_ char *comm = NULL, *u = NULL;

                if (!timeout)
                        return 0;

                (void) get_process_comm(offending->pid, &comm);
                u = uid_to_name(offending->uid);

                log_notice("Delay lock is active (UID "UID_FMT"/%s, PID "PID_FMT"/%s) but inhibitor timeout is reached.",
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

static int manager_inhibit_timeout_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *manager = userdata;
        int r;

        assert(manager);
        assert(manager->inhibit_timeout_source == s);

        r = manager_dispatch_delayed(manager, true);
        return (r < 0) ? r : 0;
}

static int delay_shutdown_or_sleep(
                Manager *m,
                InhibitWhat w,
                const char *unit_name) {

        int r;
        usec_t timeout_val;

        assert(m);
        assert(w >= 0);
        assert(w < _INHIBIT_WHAT_MAX);
        assert(unit_name);

        timeout_val = now(CLOCK_MONOTONIC) + m->inhibit_delay_max;

        if (m->inhibit_timeout_source) {
                r = sd_event_source_set_time(m->inhibit_timeout_source, timeout_val);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_time() failed: %m");

                r = sd_event_source_set_enabled(m->inhibit_timeout_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_enabled() failed: %m");
        } else {
                r = sd_event_add_time(m->event, &m->inhibit_timeout_source, CLOCK_MONOTONIC,
                                      timeout_val, 0, manager_inhibit_timeout_handler, m);
                if (r < 0)
                        return r;
        }

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

static int verify_shutdown_creds(
                Manager *m,
                sd_bus_message *message,
                InhibitWhat w,
                bool interactive,
                const char *action,
                const char *action_multiple_sessions,
                const char *action_ignore_inhibit,
                sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        bool multiple_sessions, blocked;
        uid_t uid;
        int r;

        assert(m);
        assert(message);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, uid, NULL);

        if (multiple_sessions && action_multiple_sessions) {
                r = bus_verify_polkit_async(message, CAP_SYS_BOOT, action_multiple_sessions, NULL, interactive, UID_INVALID, &m->polkit_registry, error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (blocked && action_ignore_inhibit) {
                r = bus_verify_polkit_async(message, CAP_SYS_BOOT, action_ignore_inhibit, NULL, interactive, UID_INVALID, &m->polkit_registry, error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (!multiple_sessions && !blocked && action) {
                r = bus_verify_polkit_async(message, CAP_SYS_BOOT, action, NULL, interactive, UID_INVALID, &m->polkit_registry, error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        return 0;
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
                sd_bus_error *error) {

        int interactive, r;

        assert(m);
        assert(message);
        assert(unit_name);
        assert(w >= 0);
        assert(w <= _INHIBIT_WHAT_MAX);

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

        r = verify_shutdown_creds(m, message, w, interactive, action, action_multiple_sessions,
                                  action_ignore_inhibit, error);
        if (r != 0)
                return r;

        r = bus_manager_shutdown_or_sleep_now_or_later(m, unit_name, w, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_POWEROFF_TARGET,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.power-off",
                        "org.freedesktop.login1.power-off-multiple-sessions",
                        "org.freedesktop.login1.power-off-ignore-inhibit",
                        NULL,
                        error);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_REBOOT_TARGET,
                        INHIBIT_SHUTDOWN,
                        "org.freedesktop.login1.reboot",
                        "org.freedesktop.login1.reboot-multiple-sessions",
                        "org.freedesktop.login1.reboot-ignore-inhibit",
                        NULL,
                        error);
}

static int method_suspend(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_SUSPEND_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.suspend",
                        "org.freedesktop.login1.suspend-multiple-sessions",
                        "org.freedesktop.login1.suspend-ignore-inhibit",
                        "suspend",
                        error);
}

static int nologin_timeout_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *m = userdata;
        int r;

        log_info("Creating /run/nologin, blocking further logins...");

        r = write_string_file("/run/nologin", "System is going down.", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                log_error_errno(r, "Failed to create /run/nologin: %m");
        else
                m->unlink_nologin = true;

        return 0;
}

static int update_schedule_file(Manager *m) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        r = mkdir_safe_label("/run/systemd/shutdown", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create shutdown subdirectory: %m");

        r = fopen_temporary("/run/systemd/shutdown/scheduled", &f, &temp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to save information about scheduled shutdowns: %m");

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "USEC="USEC_FMT"\n"
                "WARN_WALL=%i\n"
                "MODE=%s\n",
                m->scheduled_shutdown_timeout,
                m->enable_wall_messages,
                m->scheduled_shutdown_type);

        if (!isempty(m->wall_message)) {
                _cleanup_free_ char *t;

                t = cescape(m->wall_message);
                if (!t) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "WALL_MESSAGE=%s\n", t);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, "/run/systemd/shutdown/scheduled") < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(temp_path);
        (void) unlink("/run/systemd/shutdown/scheduled");

        return log_error_errno(r, "Failed to write information about scheduled shutdowns: %m");
}

static int manager_scheduled_shutdown_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        Manager *m = userdata;
        const char *target;
        int r;

        assert(m);

        if (isempty(m->scheduled_shutdown_type))
                return 0;

        if (streq(m->scheduled_shutdown_type, "halt"))
                target = SPECIAL_HALT_TARGET;
        else if (streq(m->scheduled_shutdown_type, "poweroff"))
                target = SPECIAL_POWEROFF_TARGET;
        else
                target = SPECIAL_REBOOT_TARGET;

        r = execute_shutdown_or_sleep(m, 0, target, &error);
        if (r < 0)
                return log_error_errno(r, "Unable to execute transition to %s: %m", target);

        return 0;
}

static int method_schedule_shutdown(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        const char *action_multiple_sessions = NULL;
        const char *action_ignore_inhibit = NULL;
        const char *action = NULL;
        uint64_t elapse;
        char *type;
        int r;

        assert(m);
        assert(message);

        r = sd_bus_message_read(message, "st", &type, &elapse);
        if (r < 0)
                return r;

        if (startswith(type, "dry-")) {
                type += 4;
                m->shutdown_dry_run = true;
        }

        if (streq(type, "reboot")) {
                action = "org.freedesktop.login1.reboot";
                action_multiple_sessions = "org.freedesktop.login1.reboot-multiple-sessions";
                action_ignore_inhibit = "org.freedesktop.login1.reboot-ignore-inhibit";
        } else if (streq(type, "halt")) {
                action = "org.freedesktop.login1.halt";
                action_multiple_sessions = "org.freedesktop.login1.halt-multiple-sessions";
                action_ignore_inhibit = "org.freedesktop.login1.halt-ignore-inhibit";
        } else if (streq(type, "poweroff")) {
                action = "org.freedesktop.login1.poweroff";
                action_multiple_sessions = "org.freedesktop.login1.poweroff-multiple-sessions";
                action_ignore_inhibit = "org.freedesktop.login1.poweroff-ignore-inhibit";
        } else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unsupported shutdown type");

        r = verify_shutdown_creds(m, message, INHIBIT_SHUTDOWN, false,
                                  action, action_multiple_sessions, action_ignore_inhibit, error);
        if (r != 0)
                return r;

        if (m->scheduled_shutdown_timeout_source) {
                r = sd_event_source_set_time(m->scheduled_shutdown_timeout_source, elapse);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_time() failed: %m");

                r = sd_event_source_set_enabled(m->scheduled_shutdown_timeout_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_enabled() failed: %m");
        } else {
                r = sd_event_add_time(m->event, &m->scheduled_shutdown_timeout_source,
                                      CLOCK_REALTIME, elapse, 0, manager_scheduled_shutdown_handler, m);
                if (r < 0)
                        return log_error_errno(r, "sd_event_add_time() failed: %m");
        }

        r = free_and_strdup(&m->scheduled_shutdown_type, type);
        if (r < 0) {
                m->scheduled_shutdown_timeout_source = sd_event_source_unref(m->scheduled_shutdown_timeout_source);
                return log_oom();
        }

        if (m->nologin_timeout_source) {
                r = sd_event_source_set_time(m->nologin_timeout_source, elapse);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_time() failed: %m");

                r = sd_event_source_set_enabled(m->nologin_timeout_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_enabled() failed: %m");
        } else {
                r = sd_event_add_time(m->event, &m->nologin_timeout_source,
                                      CLOCK_REALTIME, elapse - 5 * USEC_PER_MINUTE, 0, nologin_timeout_handler, m);
                if (r < 0)
                        return log_error_errno(r, "sd_event_add_time() failed: %m");
        }

        m->scheduled_shutdown_timeout = elapse;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_TTY|SD_BUS_CREDS_UID, &creds);
        if (r >= 0) {
                const char *tty;

                (void) sd_bus_creds_get_uid(creds, &m->scheduled_shutdown_uid);
                (void) sd_bus_creds_get_tty(creds, &tty);

                r = free_and_strdup(&m->scheduled_shutdown_tty, tty);
                if (r < 0) {
                        m->scheduled_shutdown_timeout_source = sd_event_source_unref(m->scheduled_shutdown_timeout_source);
                        return log_oom();
                }
        }

        r = manager_setup_wall_message_timer(m);
        if (r < 0)
                return r;

        if (!isempty(type)) {
                r = update_schedule_file(m);
                if (r < 0)
                        return r;
        } else
                (void) unlink("/run/systemd/shutdown/scheduled");

        return sd_bus_reply_method_return(message, NULL);
}

static int method_cancel_scheduled_shutdown(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        bool cancelled;

        assert(m);
        assert(message);

        cancelled = m->scheduled_shutdown_type != NULL;
        reset_scheduled_shutdown(m);

        if (cancelled) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                const char *tty = NULL;
                uid_t uid = 0;
                int r;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_TTY|SD_BUS_CREDS_UID, &creds);
                if (r >= 0) {
                        (void) sd_bus_creds_get_uid(creds, &uid);
                        (void) sd_bus_creds_get_tty(creds, &tty);
                }

                utmp_wall("The system shutdown has been cancelled",
                          uid_to_name(uid), tty, logind_wall_tty_filter, m);
        }

        return sd_bus_reply_method_return(message, "b", cancelled);
}

static int method_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_HIBERNATE_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hibernate",
                        error);
}

static int method_hybrid_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        SPECIAL_HYBRID_SLEEP_TARGET,
                        INHIBIT_SLEEP,
                        "org.freedesktop.login1.hibernate",
                        "org.freedesktop.login1.hibernate-multiple-sessions",
                        "org.freedesktop.login1.hibernate-ignore-inhibit",
                        "hybrid-sleep",
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

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, w, INHIBIT_BLOCK, NULL, false, true, uid, NULL);

        if (multiple_sessions) {
                r = bus_test_polkit(message, CAP_SYS_BOOT, action_multiple_sessions, NULL, UID_INVALID, &challenge, error);
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
                r = bus_test_polkit(message, CAP_SYS_BOOT, action_ignore_inhibit, NULL, UID_INVALID, &challenge, error);
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

                r = bus_test_polkit(message, CAP_SYS_BOOT, action, NULL, UID_INVALID, &challenge, error);
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

static int method_can_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

static int method_can_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

static int method_can_suspend(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

static int method_can_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

static int method_can_hybrid_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

static int property_get_reboot_to_firmware_setup(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        r = efi_get_reboot_to_firmware();
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        return sd_bus_message_append(reply, "b", r > 0);
}

static int method_set_reboot_to_firmware_setup(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        int b, r;
        Manager *m = userdata;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message,
                                    CAP_SYS_ADMIN,
                                    "org.freedesktop.login1.set-reboot-to-firmware-setup",
                                    NULL,
                                    false,
                                    UID_INVALID,
                                    &m->polkit_registry,
                                    error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = efi_set_reboot_to_firmware(b);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_can_reboot_to_firmware_setup(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        int r;
        bool challenge;
        const char *result;
        Manager *m = userdata;

        assert(message);
        assert(m);

        r = efi_reboot_to_firmware_supported();
        if (r == -EOPNOTSUPP)
                return sd_bus_reply_method_return(message, "s", "na");
        else if (r < 0)
                return r;

        r = bus_test_polkit(message,
                            CAP_SYS_ADMIN,
                            "org.freedesktop.login1.set-reboot-to-firmware-setup",
                            NULL,
                            UID_INVALID,
                            &challenge,
                            error);
        if (r < 0)
                return r;

        if (r > 0)
                result = "yes";
        else if (challenge)
                result = "challenge";
        else
                result = "no";

        return sd_bus_reply_method_return(message, "s", result);
}

static int method_set_wall_message(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        int r;
        Manager *m = userdata;
        char *wall_message;
        int enable_wall_messages;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "sb", &wall_message, &enable_wall_messages);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message,
                                    CAP_SYS_ADMIN,
                                    "org.freedesktop.login1.set-wall-message",
                                    NULL,
                                    false,
                                    UID_INVALID,
                                    &m->polkit_registry,
                                    error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        if (isempty(wall_message))
                m->wall_message = mfree(m->wall_message);
        else {
                r = free_and_strdup(&m->wall_message, wall_message);
                if (r < 0)
                        return log_oom();
        }

        m->enable_wall_messages = enable_wall_messages;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_inhibit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
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

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_BOOT,
                        w == INHIBIT_SHUTDOWN             ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-shutdown" : "org.freedesktop.login1.inhibit-delay-shutdown") :
                        w == INHIBIT_SLEEP                ? (mm == INHIBIT_BLOCK ? "org.freedesktop.login1.inhibit-block-sleep"    : "org.freedesktop.login1.inhibit-delay-sleep") :
                        w == INHIBIT_IDLE                 ? "org.freedesktop.login1.inhibit-block-idle" :
                        w == INHIBIT_HANDLE_POWER_KEY     ? "org.freedesktop.login1.inhibit-handle-power-key" :
                        w == INHIBIT_HANDLE_SUSPEND_KEY   ? "org.freedesktop.login1.inhibit-handle-suspend-key" :
                        w == INHIBIT_HANDLE_HIBERNATE_KEY ? "org.freedesktop.login1.inhibit-handle-hibernate-key" :
                                                            "org.freedesktop.login1.inhibit-handle-lid-switch",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pid(creds, &pid);
        if (r < 0)
                return r;

        do {
                id = mfree(id);

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

        SD_BUS_WRITABLE_PROPERTY("EnableWallMessages", "b", NULL, NULL, offsetof(Manager, enable_wall_messages), 0),
        SD_BUS_WRITABLE_PROPERTY("WallMessage", "s", NULL, NULL, offsetof(Manager, wall_message), 0),

        SD_BUS_PROPERTY("NAutoVTs", "u", NULL, offsetof(Manager, n_autovts), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillOnlyUsers", "as", NULL, offsetof(Manager, kill_only_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillExcludeUsers", "as", NULL, offsetof(Manager, kill_exclude_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillUserProcesses", "b", NULL, offsetof(Manager, kill_user_processes), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RebootToFirmwareSetup", "b", property_get_reboot_to_firmware_setup, 0, SD_BUS_VTABLE_PROPERTY_CONST),
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
        SD_BUS_PROPERTY("HandleLidSwitchDocked", "s", property_get_handle_action, offsetof(Manager, handle_lid_switch_docked), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HoldoffTimeoutUSec", "t", NULL, offsetof(Manager, holdoff_timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleAction", "s", property_get_handle_action, offsetof(Manager, idle_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleActionUSec", "t", NULL, offsetof(Manager, idle_action_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PreparingForShutdown", "b", property_get_preparing, 0, 0),
        SD_BUS_PROPERTY("PreparingForSleep", "b", property_get_preparing, 0, 0),
        SD_BUS_PROPERTY("ScheduledShutdown", "(st)", property_get_scheduled_shutdown, 0, 0),
        SD_BUS_PROPERTY("Docked", "b", property_get_docked, 0, 0),

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
        SD_BUS_METHOD("LockSession", "s", NULL, method_lock_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnlockSession", "s", NULL, method_lock_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LockSessions", NULL, NULL, method_lock_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnlockSessions", NULL, NULL, method_lock_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("KillSession", "ssi", NULL, method_kill_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("KillUser", "ui", NULL, method_kill_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TerminateSession", "s", NULL, method_terminate_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TerminateUser", "u", NULL, method_terminate_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TerminateSeat", "s", NULL, method_terminate_seat, SD_BUS_VTABLE_UNPRIVILEGED),
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
        SD_BUS_METHOD("ScheduleShutdown", "st", NULL, method_schedule_shutdown, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CancelScheduledShutdown", NULL, "b", method_cancel_scheduled_shutdown, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Inhibit", "ssss", "h", method_inhibit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CanRebootToFirmwareSetup", NULL, "s", method_can_reboot_to_firmware_setup, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetRebootToFirmwareSetup", "b", NULL, method_set_reboot_to_firmware_setup, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetWallMessage", "sb", NULL, method_set_wall_message, SD_BUS_VTABLE_UNPRIVILEGED),

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

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *result, *unit;
        Manager *m = userdata;
        Session *session;
        uint32_t id;
        User *user;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (m->action_job && streq(m->action_job, path)) {
                log_info("Operation '%s' finished.", inhibit_what_to_string(m->action_what));

                /* Tell people that they now may take a lock again */
                send_prepare_for(m, m->action_what, false);

                m->action_job = mfree(m->action_job);
                m->action_unit = NULL;
                m->action_what = 0;
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session && streq_ptr(path, session->scope_job)) {
                session->scope_job = mfree(session->scope_job);
                session_jobs_reply(session, unit, result);

                session_save(session);
                user_save(session->user);
                session_add_to_gc_queue(session);
        }

        user = hashmap_get(m->user_units, unit);
        if (user &&
            (streq_ptr(path, user->service_job) ||
             streq_ptr(path, user->slice_job))) {

                if (streq_ptr(path, user->service_job))
                        user->service_job = mfree(user->service_job);

                if (streq_ptr(path, user->slice_job))
                        user->slice_job = mfree(user->slice_job);

                LIST_FOREACH(sessions_by_user, session, user->sessions)
                        session_jobs_reply(session, unit, result);

                user_save(user);
                user_add_to_gc_queue(user);
        }

        return 0;
}

int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = userdata;
        Session *session;
        User *user;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *unit = NULL;
        Manager *m = userdata;
        const char *path;
        Session *session;
        User *user;
        int r;

        assert(message);
        assert(m);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r == -EINVAL) /* not a unit */
                return 0;
        if (r < 0) {
                log_oom();
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Session *session;
        Iterator i;
        int b, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our sessions */
        log_debug("System manager has been reloaded, rechecking sessions...");

        HASHMAP_FOREACH(session, m->sessions, i)
                session_add_to_gc_queue(session);

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

int manager_start_slice(
                Manager *manager,
                const char *slice,
                const char *description,
                const char *after,
                const char *after2,
                uint64_t tasks_max,
                sd_bus_error *error,
                char **job) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        int r;

        assert(manager);
        assert(slice);

        r = sd_bus_message_new_method_call(
                        manager->bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", strempty(slice), "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

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

        r = sd_bus_message_append(m, "(sv)", "TasksMax", "t", tasks_max);
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

int manager_start_scope(
                Manager *manager,
                const char *scope,
                pid_t pid,
                const char *slice,
                const char *description,
                const char *after,
                const char *after2,
                uint64_t tasks_max,
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

        r = sd_bus_message_append(m, "(sv)", "TasksMax", "t", tasks_max);
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
                        "ss", unit, "replace");
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
