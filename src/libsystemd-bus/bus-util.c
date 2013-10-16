/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "sd-event.h"
#include "sd-bus.h"

#include "util.h"
#include "macro.h"
#include "def.h"

#include "bus-util.h"

static int quit_callback(sd_bus *bus, sd_bus_message *m, void *userdata) {
        sd_event *e = userdata;

        assert(bus);
        assert(m);
        assert(e);

        sd_event_request_quit(e);
        return 1;
}

int bus_async_unregister_and_quit(sd_event *e, sd_bus *bus, const char *name) {
        _cleanup_free_ char *match = NULL;
        int r;

        assert(e);
        assert(bus);
        assert(name);

        r = asprintf(&match, "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameLost',arg0='%s'", name);
        if (r < 0)
                return r;

        r = sd_bus_add_match(bus, match, quit_callback, e);
        if (r < 0)
                return r;

        r = sd_bus_release_name(bus, name);
        if (r < 0)
                return r;

        if (r != SD_BUS_NAME_RELEASED)
                return -EIO;

        return 0;
}

int bus_event_loop_with_idle(sd_event *e, sd_bus *bus, const char *name, usec_t timeout) {
        bool exiting = false;
        int r;

        assert(e);
        assert(bus);
        assert(name);

        for (;;) {
                r = sd_event_get_state(e);
                if (r < 0)
                        return r;

                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_run(e, exiting ? (uint64_t) -1 : DEFAULT_EXIT_USEC);
                if (r < 0)
                        return r;

                if (r == 0 && !exiting) {
                        r = bus_async_unregister_and_quit(e, bus, name);
                        if (r < 0)
                                return r;

                        exiting = true;
                }
        }

        return 0;
}

int bus_property_get_tristate(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                sd_bus_error *error,
                void *userdata) {

        int *tristate = userdata;
        int r;

        r = sd_bus_message_append(reply, "b", *tristate > 0);
        if (r < 0)
                return r;

        return 1;
}

int bus_verify_polkit(
                sd_bus *bus,
                sd_bus_message *m,
                const char *action,
                bool interactive,
                bool *_challenge,
                sd_bus_error *e) {

        const char *sender;
        uid_t uid;
        int r;

        assert(bus);
        assert(m);
        assert(action);

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EBADMSG;

        r = sd_bus_get_owner_uid(bus, sender, &uid);
        if (r < 0)
                return r;

        if (uid == 0)
                return 1;

#ifdef ENABLE_POLKIT
        else {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                bool authorized = false, challenge = false;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.PolicyKit1",
                                "/org/freedesktop/PolicyKit1/Authority",
                                "org.freedesktop.PolicyKit1.Authority",
                                "CheckAuthorization",
                                e,
                                &reply,
                                "(sa{sv})sa{ss}us",
                                "system-bus-name", 1, "name", "s", sender,
                                action,
                                0,
                                interactive ? 1 : 0,
                                "");

                if (r < 0) {
                        /* Treat no PK available as access denied */
                        if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN)) {
                                sd_bus_error_free(e);
                                return -EACCES;
                        }

                        return r;
                }

                r = sd_bus_message_read(reply, "(bb)", &authorized, &challenge);
                if (r < 0)
                        return r;

                if (authorized)
                        return 1;

                if (_challenge) {
                        *_challenge = challenge;
                        return 0;
                }
        }
#endif

        return -EACCES;
}

#ifdef ENABLE_POLKIT

typedef struct AsyncPolkitQuery {
        sd_bus_message *request, *reply;
        sd_bus_message_handler_t callback;
        void *userdata;
        uint64_t serial;
} AsyncPolkitQuery;

static int async_polkit_callback(sd_bus *bus, sd_bus_message *reply, void *userdata) {
        AsyncPolkitQuery *q = userdata;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(reply);
        assert(q);

        q->reply = sd_bus_message_ref(reply);
        q->serial = 0;

        m = sd_bus_message_ref(q->request);

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        r = q->callback(bus, m, q->userdata);
        if (r < 0)
                return r;

        return 1;
}

static void async_polkit_query_free(sd_bus *b, AsyncPolkitQuery *q) {

        if (!q)
                return;

        if (q->serial >  0 && b)
                sd_bus_send_with_reply_cancel(b, q->serial);

        sd_bus_message_unref(q->request);
        sd_bus_message_unref(q->reply);
        free(q);
}

#endif

int bus_verify_polkit_async(
                sd_bus *bus,
                Hashmap **registry,
                sd_bus_message *m,
                const char *action,
                bool interactive,
                sd_bus_error *error,
                sd_bus_message_handler_t callback,
                void *userdata) {

#ifdef ENABLE_POLKIT
        _cleanup_bus_message_unref_ sd_bus_message *pk = NULL;
        AsyncPolkitQuery *q;
#endif
        const char *sender;
        uid_t uid;
        int r;

        assert(bus);
        assert(registry);
        assert(m);
        assert(action);

#ifdef ENABLE_POLKIT
        q = hashmap_remove(*registry, m);
        if (q) {
                bool authorized, challenge;

                /* This is the second invocation of this function, and
                 * there's already a response from polkit, let's
                 * process it */
                assert(q->reply);

                if (sd_bus_message_is_method_error(q->reply, NULL)) {
                        const sd_bus_error *e;

                        /* Treat no PK available as access denied */
                        if (sd_bus_message_is_method_error(q->reply, SD_BUS_ERROR_SERVICE_UNKNOWN)) {
                                async_polkit_query_free(bus, q);
                                return -EACCES;
                        }

                        e = sd_bus_message_get_error(q->reply);
                        sd_bus_error_copy(error, e);
                        r = sd_bus_error_get_errno(e);

                        async_polkit_query_free(bus, q);
                        return r;
                }

                r = sd_bus_message_enter_container(q->reply, 'r', "bba{ss}");
                if (r >= 0)
                        r = sd_bus_message_read(q->reply, "bb", &authorized, &challenge);

                async_polkit_query_free(bus, q);

                if (r < 0)
                        return r;

                if (authorized)
                        return 1;

                return -EACCES;
        }
#endif

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EBADMSG;

        r = sd_bus_get_owner_uid(bus, sender, &uid);
        if (r < 0)
                return r;

        if (uid == 0)
                return 1;
#ifdef ENABLE_POLKIT

        r = hashmap_ensure_allocated(registry, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization",
                        &pk);
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        pk,
                        "(sa{sv})sa{ss}us",
                        "system-bus-name", 1, "name", "s", sender,
                        action,
                        0,
                        interactive ? 1 : 0,
                        "");
        if (r < 0)
                return r;

        q = new0(AsyncPolkitQuery, 1);
        if (!q)
                return -ENOMEM;

        q->request = sd_bus_message_ref(m);
        q->callback = callback;
        q->userdata = userdata;

        r = hashmap_put(*registry, m, q);
        if (r < 0) {
                async_polkit_query_free(bus, q);
                return r;
        }

        r = sd_bus_send_with_reply(bus, pk, async_polkit_callback, q, 0, &q->serial);
        if (r < 0)
                return r;

        return 0;
#endif

        return -EACCES;
}

void bus_verify_polkit_async_registry_free(sd_bus *bus, Hashmap *registry) {
#ifdef ENABLE_POLKIT
        AsyncPolkitQuery *q;

        while ((q = hashmap_steal_first(registry)))
                async_polkit_query_free(bus, q);

        hashmap_free(registry);
#endif
}
