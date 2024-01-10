/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "logind-dbus.h"
#include "logind-polkit.h"
#include "logind-seat-dbus.h"
#include "logind-seat.h"
#include "logind-session-dbus.h"
#include "logind.h"
#include "missing_capability.h"
#include "strv.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_const_true, "b", true);
static BUS_DEFINE_PROPERTY_GET(property_get_can_tty, "b", Seat, seat_can_tty);
static BUS_DEFINE_PROPERTY_GET(property_get_can_graphical, "b", Seat, seat_can_graphical);

static int property_get_active_session(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Seat *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = s->active ? session_bus_path(s->active) : strdup("/");
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", s->active ? s->active->id : "", p);
}

static int property_get_sessions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Seat *s = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

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

        Seat *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

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

        Seat *s = ASSERT_PTR(userdata);
        dual_timestamp t;
        uint64_t u;
        int r;

        assert(bus);
        assert(reply);

        r = seat_get_idle_hint(s, &t);
        if (r < 0)
                return r;

        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        return sd_bus_message_append(reply, "t", u);
}

int bus_seat_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        &s->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = seat_stop_sessions(s, /* force = */ true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = ASSERT_PTR(userdata);
        const char *name;
        Session *session;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        session = hashmap_get(s->manager->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        if (session->seat != s)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_NOT_ON_SEAT, "Session %s not on seat %s", name, s->id);

        r = check_polkit_chvt(message, s->manager, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = ASSERT_PTR(userdata);
        unsigned to;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &to);
        if (r < 0)
                return r;

        if (to <= 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid virtual terminal");

        r = check_polkit_chvt(message, s->manager, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = seat_switch_to(s, to);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to_next(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = check_polkit_chvt(message, s->manager, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = seat_switch_to_next(s);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_to_previous(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Seat *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = check_polkit_chvt(message, s->manager, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = seat_switch_to_previous(s);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int seat_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *e = NULL;
        sd_bus_message *message;
        Manager *m = ASSERT_PTR(userdata);
        const char *p;
        Seat *seat;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        p = startswith(path, "/org/freedesktop/login1/seat/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        message = sd_bus_get_current_message(bus);

        r = manager_get_seat_from_creds(m, message, e, error, &seat);
        if (r == -ENXIO) {
                sd_bus_error_free(error);
                return 0;
        }
        if (r < 0)
                return r;

        *found = seat;
        return 1;
}

char *seat_bus_path(Seat *s) {
        _cleanup_free_ char *t = NULL;

        assert(s);

        t = bus_label_escape(s->id);
        if (!t)
                return NULL;

        return strjoin("/org/freedesktop/login1/seat/", t);
}

static int seat_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        sd_bus_message *message;
        Manager *m = userdata;
        Seat *seat;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(seat, m->seats) {
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
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r >= 0) {
                        bool may_auto = false;
                        const char *name;

                        r = sd_bus_creds_get_session(creds, &name);
                        if (r >= 0) {
                                Session *session;

                                session = hashmap_get(m->sessions, name);
                                if (session && session->seat) {
                                        r = strv_extend(&l, "/org/freedesktop/login1/seat/self");
                                        if (r < 0)
                                                return r;

                                        may_auto = true;
                                }
                        }

                        if (!may_auto) {
                                uid_t uid;

                                r = sd_bus_creds_get_owner_uid(creds, &uid);
                                if (r >= 0) {
                                        User *user;

                                        user = hashmap_get(m->users, UID_TO_PTR(uid));
                                        may_auto = user && user->display && user->display->seat;
                                }
                        }

                        if (may_auto) {
                                r = strv_extend(&l, "/org/freedesktop/login1/seat/auto");
                                if (r < 0)
                                        return r;
                        }
                }
        }

        *nodes = TAKE_PTR(l);
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

static const sd_bus_vtable seat_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Seat, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ActiveSession", "(so)", property_get_active_session, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanMultiSession", "b", property_get_const_true, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("CanTTY", "b", property_get_can_tty, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanGraphical", "b", property_get_can_graphical, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Sessions", "a(so)", property_get_sessions, 0, 0),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD("Terminate", NULL, NULL, bus_seat_method_terminate, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("ActivateSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_activate_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SwitchTo",
                                SD_BUS_ARGS("u", vtnr),
                                SD_BUS_NO_RESULT,
                                method_switch_to,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD("SwitchToNext", NULL, NULL, method_switch_to_next, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SwitchToPrevious", NULL, NULL, method_switch_to_previous, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation seat_object = {
        "/org/freedesktop/login1/seat",
        "org.freedesktop.login1.Seat",
        .fallback_vtables = BUS_FALLBACK_VTABLES({seat_vtable, seat_object_find}),
        .node_enumerator = seat_node_enumerator,
};
