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
#include "bus-util.h"
#include "formats-util.h"
#include "logind-user.h"
#include "logind.h"
#include "strv.h"
#include "user-util.h"

static int property_get_display(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        User *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        p = u->display ? session_bus_path(u->display) : strdup("/");
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", u->display ? u->display->id : "", p);
}

static int property_get_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", user_state_to_string(user_get_state(u)));
}

static int property_get_sessions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = userdata;
        Session *session;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = sd_bus_message_open_container(reply, 'a', "(so)");
        if (r < 0)
                return r;

        LIST_FOREACH(sessions_by_user, session, u->sessions) {
                _cleanup_free_ char *p = NULL;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(so)", session->id, p);
                if (r < 0)
                        return r;

        }

        return sd_bus_message_close_container(reply);
}

static int property_get_idle_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "b", user_get_idle_hint(u, NULL) > 0);
}

static int property_get_idle_since_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = userdata;
        dual_timestamp t = DUAL_TIMESTAMP_NULL;
        uint64_t k;

        assert(bus);
        assert(reply);
        assert(u);

        user_get_idle_hint(u, &t);
        k = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        return sd_bus_message_append(reply, "t", k);
}

static int property_get_linger(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = user_check_linger_file(u);

        return sd_bus_message_append(reply, "b", r > 0);
}

int bus_user_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        User *u = userdata;
        int r;

        assert(message);
        assert(u);

        r = bus_verify_polkit_async(
                        message,
                        CAP_KILL,
                        "org.freedesktop.login1.manage",
                        NULL,
                        false,
                        u->uid,
                        &u->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = user_stop(u, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_user_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        User *u = userdata;
        int32_t signo;
        int r;

        assert(message);
        assert(u);

        r = bus_verify_polkit_async(
                        message,
                        CAP_KILL,
                        "org.freedesktop.login1.manage",
                        NULL,
                        false,
                        u->uid,
                        &u->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(message, "i", &signo);
        if (r < 0)
                return r;

        if (signo <= 0 || signo >= _NSIG)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        r = user_kill(u, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable user_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(User, uid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(User, gid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(User, name), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("Timestamp", offsetof(User, timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimePath", "s", NULL, offsetof(User, runtime_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Service", "s", NULL, offsetof(User, service), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Slice", "s", NULL, offsetof(User, slice), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Display", "(so)", property_get_display, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("State", "s", property_get_state, 0, 0),
        SD_BUS_PROPERTY("Sessions", "a(so)", property_get_sessions, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Linger", "b", property_get_linger, 0, 0),

        SD_BUS_METHOD("Terminate", NULL, NULL, bus_user_method_terminate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Kill", "i", NULL, bus_user_method_kill, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

int user_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        uid_t uid;
        User *user;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        if (streq(path, "/org/freedesktop/login1/user/self")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                sd_bus_message *message;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_owner_uid(creds, &uid);
        } else {
                const char *p;

                p = startswith(path, "/org/freedesktop/login1/user/_");
                if (!p)
                        return 0;

                r = parse_uid(p, &uid);
        }
        if (r < 0)
                return 0;

        user = hashmap_get(m->users, UID_TO_PTR(uid));
        if (!user)
                return 0;

        *found = user;
        return 1;
}

char *user_bus_path(User *u) {
        char *s;

        assert(u);

        if (asprintf(&s, "/org/freedesktop/login1/user/_"UID_FMT, u->uid) < 0)
                return NULL;

        return s;
}

int user_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        sd_bus_message *message;
        Manager *m = userdata;
        User *user;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(user, m->users, i) {
                char *p;

                p = user_bus_path(user);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        message = sd_bus_get_current_message(bus);
        if (message) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                uid_t uid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r >= 0) {
                        r = sd_bus_creds_get_owner_uid(creds, &uid);
                        if (r >= 0) {
                                user = hashmap_get(m->users, UID_TO_PTR(uid));
                                if (user) {
                                        r = strv_extend(&l, "/org/freedesktop/login1/user/self");
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

int user_send_signal(User *u, bool new_user) {
        _cleanup_free_ char *p = NULL;

        assert(u);

        p = user_bus_path(u);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        u->manager->bus,
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        new_user ? "UserNew" : "UserRemoved",
                        "uo", (uint32_t) u->uid, p);
}

int user_send_changed(User *u, const char *properties, ...) {
        _cleanup_free_ char *p = NULL;
        char **l;

        assert(u);

        if (!u->started)
                return 0;

        p = user_bus_path(u);
        if (!p)
                return -ENOMEM;

        l = strv_from_stdarg_alloca(properties);

        return sd_bus_emit_properties_changed_strv(u->manager->bus, p, "org.freedesktop.login1.User", l);
}
