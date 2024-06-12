/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "format-util.h"
#include "logind-dbus.h"
#include "logind-session-dbus.h"
#include "logind-user-dbus.h"
#include "logind-user.h"
#include "logind.h"
#include "missing_capability.h"
#include "signal-util.h"
#include "strv.h"
#include "user-util.h"

static int property_get_uid(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "u", (uint32_t) u->user_record->uid);
}

static int property_get_gid(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "u", (uint32_t) u->user_record->gid);
}

static int property_get_name(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", u->user_record->user_name);
}

static BUS_DEFINE_PROPERTY_GET2(property_get_state, "s", User, user_get_state, user_state_to_string);

static int property_get_display(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        User *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = u->display ? session_bus_path(u->display) : strdup("/");
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", u->display ? u->display->id : "", p);
}

static int property_get_sessions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        User *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

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

        User *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

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

        User *u = ASSERT_PTR(userdata);
        dual_timestamp t = DUAL_TIMESTAMP_NULL;
        uint64_t k;

        assert(bus);
        assert(reply);

        (void) user_get_idle_hint(u, &t);
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

        User *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = user_check_linger_file(u);

        return sd_bus_message_append(reply, "b", r > 0);
}

int bus_user_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        User *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        u->user_record->uid,
                        /* flags= */ 0,
                        &u->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = user_stop(u, /* force = */ true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_user_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        User *u = ASSERT_PTR(userdata);
        int32_t signo;
        int r;

        assert(message);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        u->user_record->uid,
                        /* flags= */ 0,
                        &u->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(message, "i", &signo);
        if (r < 0)
                return r;

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        r = user_kill(u, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int user_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        User *user;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        if (streq(path, "/org/freedesktop/login1/user/self")) {
                sd_bus_message *message;

                message = sd_bus_get_current_message(bus);

                r = manager_get_user_from_creds(m, message, UID_INVALID, error, &user);
                if (r == -ENXIO) {
                        sd_bus_error_free(error);
                        return 0;
                }
                if (r < 0)
                        return r;
        } else {
                const char *p;

                p = startswith(path, "/org/freedesktop/login1/user/_");
                if (!p)
                        return 0;

                r = parse_uid(p, &uid);
                if (r < 0)
                        return 0;

                user = hashmap_get(m->users, UID_TO_PTR(uid));
                if (!user)
                        return 0;
        }

        *found = user;
        return 1;
}

char* user_bus_path(User *u) {
        char *s;

        assert(u);

        if (asprintf(&s, "/org/freedesktop/login1/user/_"UID_FMT, u->user_record->uid) < 0)
                return NULL;

        return s;
}

static int user_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        sd_bus_message *message;
        Manager *m = userdata;
        User *user;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(user, m->users) {
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
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r >= 0) {
                        uid_t uid;

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

        *nodes = TAKE_PTR(l);

        return 1;
}

static const sd_bus_vtable user_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("UID", "u", property_get_uid, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("GID", "u", property_get_gid, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Name", "s", property_get_name, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("Timestamp", offsetof(User, timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimePath", "s", NULL, offsetof(User, runtime_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Service", "s", NULL, offsetof(User, service_manager_unit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Slice", "s", NULL, offsetof(User, slice), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Display", "(so)", property_get_display, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("State", "s", property_get_state, 0, 0),
        SD_BUS_PROPERTY("Sessions", "a(so)", property_get_sessions, 0, 0),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Linger", "b", property_get_linger, 0, 0),

        SD_BUS_METHOD("Terminate", NULL, NULL, bus_user_method_terminate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Kill",
                                SD_BUS_ARGS("i", signal_number),
                                SD_BUS_NO_RESULT,
                                bus_user_method_kill,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation user_object = {
        "/org/freedesktop/login1/user",
        "org.freedesktop.login1.User",
        .fallback_vtables = BUS_FALLBACK_VTABLES({user_vtable, user_object_find}),
        .node_enumerator = user_node_enumerator,
};

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
                        "uo", (uint32_t) u->user_record->uid, p);
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
