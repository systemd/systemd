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

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-label.h"
#include "bus-util.h"
#include "logind-seat.h"
#include "logind.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static int property_get_active_session(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Seat *s = userdata;

        assert(bus);
        assert(reply);
        assert(s);

        p = s->active ? session_bus_path(s->active) : strdup("/");
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", s->active ? s->active->id : "", p);
}

static int property_get_can_multi_session(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;

        assert(bus);
        assert(reply);
        assert(s);

        return sd_bus_message_append(reply, "b", seat_can_multi_session(s));
}

static int property_get_can_tty(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;

        assert(bus);
        assert(reply);
        assert(s);

        return sd_bus_message_append(reply, "b", seat_can_tty(s));
}

static int property_get_can_graphical(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;

        assert(bus);
        assert(reply);
        assert(s);

        return sd_bus_message_append(reply, "b", seat_can_graphical(s));
}

static int property_get_sessions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;
        Session *session;
        int r;

        assert(bus);
        assert(reply);
        assert(s);

        r = sd_bus_message_open_container(reply, 'a', "(so)");
        if (r < 0)
                return r;

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                _cleanup_free_ char *p = NULL;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(so)", session->id, p);
                if (r < 0)
                        return r;

        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_idle_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;

        assert(bus);
        assert(reply);
        assert(s);

        return sd_bus_message_append(reply, "b", seat_get_idle_hint(s, NULL) > 0);
}

static int property_get_idle_since_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = userdata;
        dual_timestamp t;
        uint64_t u;
        int r;

        assert(bus);
        assert(reply);
        assert(s);

        r = seat_get_idle_hint(s, &t);
        if (r < 0)
                return r;

        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        return sd_bus_message_append(reply, "t", u);
}

int bus_seat_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = userdata;
        int r;

        assert(message);
        assert(s);

        r = bus_verify_polkit_async(
                        message,
                        CAP_KILL,
                        "org.freedesktop.login1.manage",
                        NULL,
                        false,
                        UID_INVALID,
                        &s->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = seat_stop_sessions(s, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = userdata;
        const char *name;
        Session *session;
        int r;

        assert(message);
        assert(s);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(s->manager->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        if (session->seat != s)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_NOT_ON_SEAT, "Session %s not on seat %s", name, s->id);

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = userdata;
        unsigned int to;
        int r;

        assert(message);
        assert(s);

        r = sd_bus_message_read(message, "u", &to);
        if (r < 0)
                return r;

        if (to <= 0)
                return -EINVAL;

        r = seat_switch_to(s, to);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to_next(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = userdata;
        int r;

        assert(message);
        assert(s);

        r = seat_switch_to_next(s);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to_previous(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = userdata;
        int r;

        assert(message);
        assert(s);

        r = seat_switch_to_previous(s);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable seat_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Seat, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ActiveSession", "(so)", property_get_active_session, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanMultiSession", "b", property_get_can_multi_session, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanTTY", "b", property_get_can_tty, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanGraphical", "b", property_get_can_graphical, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Sessions", "a(so)", property_get_sessions, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD("Terminate", NULL, NULL, bus_seat_method_terminate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ActivateSession", "s", NULL, method_activate_session, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SwitchTo", "u", NULL, method_switch_to, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SwitchToNext", NULL, NULL, method_switch_to_next, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SwitchToPrevious", NULL, NULL, method_switch_to_previous, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

int seat_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Seat *seat;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        if (streq(path, "/org/freedesktop/login1/seat/self")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                sd_bus_message *message;
                Session *session;
                const char *name;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_SESSION|SD_BUS_CREDS_AUGMENT, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_session(creds, &name);
                if (r < 0)
                        return r;

                session = hashmap_get(m->sessions, name);
                if (!session)
                        return 0;

                seat = session->seat;
        } else {
                _cleanup_free_ char *e = NULL;
                const char *p;

                p = startswith(path, "/org/freedesktop/login1/seat/");
                if (!p)
                        return 0;

                e = bus_label_unescape(p);
                if (!e)
                        return -ENOMEM;

                seat = hashmap_get(m->seats, e);
        }

        if (!seat)
                return 0;

        *found = seat;
        return 1;
}

char *seat_bus_path(Seat *s) {
        _cleanup_free_ char *t = NULL;

        assert(s);

        t = bus_label_escape(s->id);
        if (!t)
                return NULL;

        return strappend("/org/freedesktop/login1/seat/", t);
}

int seat_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        sd_bus_message *message;
        Manager *m = userdata;
        Seat *seat;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(seat, m->seats, i) {
                char *p;

                p = seat_bus_path(seat);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        message = sd_bus_get_current_message(bus);
        if (message) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                const char *name;
                Session *session;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_SESSION|SD_BUS_CREDS_AUGMENT, &creds);
                if (r >= 0) {
                        r = sd_bus_creds_get_session(creds, &name);
                        if (r >= 0) {
                                session = hashmap_get(m->sessions, name);
                                if (session && session->seat) {
                                        r = strv_extend(&l, "/org/freedesktop/login1/seat/self");
                                        if (r < 0)
                                                return r;
                                }
                        }
                }
        }

        *nodes = l;
        l = NULL;

        return 1;
}

int seat_send_signal(Seat *s, bool new_seat) {
        _cleanup_free_ char *p = NULL;

        assert(s);

        p = seat_bus_path(s);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        s->manager->bus,
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        new_seat ? "SeatNew" : "SeatRemoved",
                        "so", s->id, p);
}

int seat_send_changed(Seat *s, const char *properties, ...) {
        _cleanup_free_ char *p = NULL;
        char **l;

        assert(s);

        if (!s->started)
                return 0;

        p = seat_bus_path(s);
        if (!p)
                return -ENOMEM;

        l = strv_from_stdarg_alloca(properties);

        return sd_bus_emit_properties_changed_strv(s->manager->bus, p, "org.freedesktop.login1.Seat", l);
}
