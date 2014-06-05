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

#include <sys/socket.h>
#include <sys/capability.h>

#include "util.h"
#include "strv.h"
#include "macro.h"
#include "def.h"
#include "path-util.h"
#include "missing.h"

#include "sd-event.h"
#include "sd-bus.h"
#include "bus-error.h"
#include "bus-message.h"
#include "bus-util.h"
#include "bus-internal.h"

static int name_owner_change_callback(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = userdata;

        assert(bus);
        assert(m);
        assert(e);

        sd_bus_close(bus);
        sd_event_exit(e, 0);

        return 1;
}

int bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name) {
        _cleanup_free_ char *match = NULL;
        const char *unique;
        int r;

        assert(e);
        assert(bus);
        assert(name);

        /* We unregister the name here and then wait for the
         * NameOwnerChanged signal for this event to arrive before we
         * quit. We do this in order to make sure that any queued
         * requests are still processed before we really exit. */

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return r;

        r = asprintf(&match,
                     "sender='org.freedesktop.DBus',"
                     "type='signal',"
                     "interface='org.freedesktop.DBus',"
                     "member='NameOwnerChanged',"
                     "path='/org/freedesktop/DBus',"
                     "arg0='%s',"
                     "arg1='%s',"
                     "arg2=''", name, unique);
        if (r < 0)
                return -ENOMEM;

        r = sd_bus_add_match(bus, NULL, match, name_owner_change_callback, e);
        if (r < 0)
                return r;

        r = sd_bus_release_name(bus, name);
        if (r < 0)
                return r;

        return 0;
}

int bus_event_loop_with_idle(
                sd_event *e,
                sd_bus *bus,
                const char *name,
                usec_t timeout,
                check_idle_t check_idle,
                void *userdata) {
        bool exiting = false;
        int r, code;

        assert(e);
        assert(bus);
        assert(name);

        for (;;) {
                bool idle;

                r = sd_event_get_state(e);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        break;

                if (check_idle)
                        idle = check_idle(userdata);
                else
                        idle = true;

                r = sd_event_run(e, exiting || !idle ? (uint64_t) -1 : timeout);
                if (r < 0)
                        return r;

                if (r == 0 && !exiting) {

                        r = sd_bus_try_close(bus);
                        if (r == -EBUSY)
                                continue;

                        if (r == -ENOTSUP) {
                                /* Fallback for dbus1 connections: we
                                 * unregister the name and wait for
                                 * the response to come through for
                                 * it */

                                r = bus_async_unregister_and_exit(e, bus, name);
                                if (r < 0)
                                        return r;

                                exiting = true;
                                continue;
                        }

                        if (r < 0)
                                return r;

                        sd_event_exit(e, 0);
                        break;
                }
        }

        r = sd_event_get_exit_code(e, &code);
        if (r < 0)
                return r;

        return code;
}

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *rep = NULL;
        int r, has_owner = 0;

        assert(c);
        assert(name);

        r = sd_bus_call_method(c,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/dbus",
                               "org.freedesktop.DBus",
                               "NameHasOwner",
                               error,
                               &rep,
                               "s",
                               name);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(rep, 'b', &has_owner);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return has_owner;
}

int bus_verify_polkit(
                sd_bus *bus,
                sd_bus_message *m,
                const char *action,
                bool interactive,
                bool *_challenge,
                sd_bus_error *e) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        uid_t uid;
        int r;

        assert(bus);
        assert(m);
        assert(action);

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_UID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        if (uid == 0)
                return 1;

#ifdef ENABLE_POLKIT
        else {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                int authorized = false, challenge = false;
                const char *sender;

                sender = sd_bus_message_get_sender(m);
                if (!sender)
                        return -EBADMSG;

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

                r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply, "bb", &authorized, &challenge);
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
        sd_bus_slot *slot;
        Hashmap *registry;
} AsyncPolkitQuery;

static void async_polkit_query_free(AsyncPolkitQuery *q) {

        if (!q)
                return;

        sd_bus_slot_unref(q->slot);

        if (q->registry && q->request)
                hashmap_remove(q->registry, q->request);

        sd_bus_message_unref(q->request);
        sd_bus_message_unref(q->reply);

        free(q);
}

static int async_polkit_callback(sd_bus *bus, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        AsyncPolkitQuery *q = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(q);

        q->slot = sd_bus_slot_unref(q->slot);
        q->reply = sd_bus_message_ref(reply);

        r = sd_bus_message_rewind(q->request, true);
        if (r < 0) {
                r = sd_bus_reply_method_errno(q->request, r, NULL);
                goto finish;
        }

        r = q->callback(bus, q->request, q->userdata, &error_buffer);
        r = bus_maybe_reply_error(q->request, r, &error_buffer);

finish:
        async_polkit_query_free(q);

        return r;
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
        const char *sender;
#endif
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        uid_t uid;
        int r;

        assert(bus);
        assert(registry);
        assert(m);
        assert(action);

#ifdef ENABLE_POLKIT
        q = hashmap_get(*registry, m);
        if (q) {
                int authorized, challenge;

                /* This is the second invocation of this function, and
                 * there's already a response from polkit, let's
                 * process it */
                assert(q->reply);

                if (sd_bus_message_is_method_error(q->reply, NULL)) {
                        const sd_bus_error *e;

                        /* Copy error from polkit reply */
                        e = sd_bus_message_get_error(q->reply);
                        sd_bus_error_copy(error, e);

                        /* Treat no PK available as access denied */
                        if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN))
                                return -EACCES;

                        return -sd_bus_error_get_errno(e);
                }

                r = sd_bus_message_enter_container(q->reply, 'r', "bba{ss}");
                if (r >= 0)
                        r = sd_bus_message_read(q->reply, "bb", &authorized, &challenge);

                if (r < 0)
                        return r;

                if (authorized)
                        return 1;

                return -EACCES;
        }
#endif

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_UID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        if (uid == 0)
                return 1;

#ifdef ENABLE_POLKIT
        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EBADMSG;

        r = hashmap_ensure_allocated(registry, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        &pk,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        pk,
                        "(sa{sv})sa{ss}us",
                        "system-bus-name", 1, "name", "s", sender,
                        action,
                        0,
                        interactive ? 1 : 0,
                        NULL);
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
                async_polkit_query_free(q);
                return r;
        }

        q->registry = *registry;

        r = sd_bus_call_async(bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0) {
                async_polkit_query_free(q);
                return r;
        }

        return 0;
#endif

        return -EACCES;
}

void bus_verify_polkit_async_registry_free(sd_bus *bus, Hashmap *registry) {
#ifdef ENABLE_POLKIT
        AsyncPolkitQuery *q;

        while ((q = hashmap_steal_first(registry)))
                async_polkit_query_free(q);

        hashmap_free(registry);
#endif
}

int bus_check_peercred(sd_bus *c) {
        struct ucred ucred;
        socklen_t l;
        int fd;

        assert(c);

        fd = sd_bus_get_fd(c);
        if (fd < 0)
                return fd;

        l = sizeof(struct ucred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0)
                return -errno;

        if (l != sizeof(struct ucred))
                return -E2BIG;

        if (ucred.uid != 0 && ucred.uid != geteuid())
                return -EPERM;

        return 1;
}

int bus_open_system_systemd(sd_bus **_bus) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        assert(_bus);

        if (geteuid() != 0)
                return sd_bus_open_system(_bus);

        /* If we are root and kdbus is not available, then let's talk
         * directly to the system instance, instead of going via the
         * bus */

#ifdef ENABLE_KDBUS
        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = sd_bus_set_address(bus, KERNEL_SYSTEM_BUS_PATH);
        if (r < 0)
                return r;

        bus->bus_client = true;

        r = sd_bus_start(bus);
        if (r >= 0) {
                *_bus = bus;
                bus = NULL;
                return 0;
        }

        bus = sd_bus_unref(bus);
#endif

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = sd_bus_set_address(bus, "unix:path=/run/systemd/private");
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return sd_bus_open_system(_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *_bus = bus;
        bus = NULL;

        return 0;
}

int bus_open_user_systemd(sd_bus **_bus) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *ee = NULL;
        const char *e;
        int r;

        /* Try via kdbus first, and then directly */

        assert(_bus);

#ifdef ENABLE_KDBUS
        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        if (asprintf(&bus->address, KERNEL_USER_BUS_FMT, getuid()) < 0)
                return -ENOMEM;

        bus->bus_client = true;

        r = sd_bus_start(bus);
        if (r >= 0) {
                *_bus = bus;
                bus = NULL;
                return 0;
        }

        bus = sd_bus_unref(bus);
#endif

        e = secure_getenv("XDG_RUNTIME_DIR");
        if (!e)
                return sd_bus_open_user(_bus);

        ee = bus_address_escape(e);
        if (!ee)
                return -ENOMEM;

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        bus->address = strjoin("unix:path=", ee, "/systemd/private", NULL);
        if (!bus->address)
                return -ENOMEM;

        r = sd_bus_start(bus);
        if (r < 0)
                return sd_bus_open_user(_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *_bus = bus;
        bus = NULL;

        return 0;
}

int bus_print_property(const char *name, sd_bus_message *property, bool all) {
        char type;
        const char *contents;
        int r;

        assert(name);
        assert(property);

        r = sd_bus_message_peek_type(property, &type, &contents);
        if (r < 0)
                return r;

        switch (type) {

        case SD_BUS_TYPE_STRING: {
                const char *s;

                r = sd_bus_message_read_basic(property, type, &s);
                if (r < 0)
                        return r;

                if (all || !isempty(s))
                        printf("%s=%s\n", name, s);

                return 1;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                bool b;

                r = sd_bus_message_read_basic(property, type, &b);
                if (r < 0)
                        return r;

                printf("%s=%s\n", name, yes_no(b));

                return 1;
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t u;

                r = sd_bus_message_read_basic(property, type, &u);
                if (r < 0)
                        return r;

                /* Yes, heuristics! But we can change this check
                 * should it turn out to not be sufficient */

                if (endswith(name, "Timestamp")) {
                        char timestamp[FORMAT_TIMESTAMP_MAX], *t;

                        t = format_timestamp(timestamp, sizeof(timestamp), u);
                        if (t || all)
                                printf("%s=%s\n", name, strempty(t));

                } else if (strstr(name, "USec")) {
                        char timespan[FORMAT_TIMESPAN_MAX];

                        printf("%s=%s\n", name, format_timespan(timespan, sizeof(timespan), u, 0));
                } else
                        printf("%s=%llu\n", name, (unsigned long long) u);

                return 1;
        }

        case SD_BUS_TYPE_UINT32: {
                uint32_t u;

                r = sd_bus_message_read_basic(property, type, &u);
                if (r < 0)
                        return r;

                if (strstr(name, "UMask") || strstr(name, "Mode"))
                        printf("%s=%04o\n", name, u);
                else
                        printf("%s=%u\n", name, (unsigned) u);

                return 1;
        }

        case SD_BUS_TYPE_INT32: {
                int32_t i;

                r = sd_bus_message_read_basic(property, type, &i);
                if (r < 0)
                        return r;

                printf("%s=%i\n", name, (int) i);
                return 1;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d;

                r = sd_bus_message_read_basic(property, type, &d);
                if (r < 0)
                        return r;

                printf("%s=%g\n", name, d);
                return 1;
        }

        case SD_BUS_TYPE_ARRAY:
                if (streq(contents, "s")) {
                        bool first = true;
                        const char *str;

                        r = sd_bus_message_enter_container(property, SD_BUS_TYPE_ARRAY, contents);
                        if (r < 0)
                                return r;

                        while((r = sd_bus_message_read_basic(property, SD_BUS_TYPE_STRING, &str)) > 0) {
                                if (first)
                                        printf("%s=", name);

                                printf("%s%s", first ? "" : " ", str);

                                first = false;
                        }
                        if (r < 0)
                                return r;

                        if (first && all)
                                printf("%s=", name);
                        if (!first || all)
                                puts("");

                        r = sd_bus_message_exit_container(property);
                        if (r < 0)
                                return r;

                        return 1;

                } else if (streq(contents, "y")) {
                        const uint8_t *u;
                        size_t n;

                        r = sd_bus_message_read_array(property, SD_BUS_TYPE_BYTE, (const void**) &u, &n);
                        if (r < 0)
                                return r;

                        if (all || n > 0) {
                                unsigned int i;

                                printf("%s=", name);

                                for (i = 0; i < n; i++)
                                        printf("%02x", u[i]);

                                puts("");
                        }

                        return 1;

                } else if (streq(contents, "u")) {
                        uint32_t *u;
                        size_t n;

                        r = sd_bus_message_read_array(property, SD_BUS_TYPE_UINT32, (const void**) &u, &n);
                        if (r < 0)
                                return r;

                        if (all || n > 0) {
                                unsigned int i;

                                printf("%s=", name);

                                for (i = 0; i < n; i++)
                                        printf("%08x", u[i]);

                                puts("");
                        }

                        return 1;
                }

                break;
        }

        return 0;
}

int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, char **filter, bool all) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);

        r = sd_bus_call_method(bus,
                        dest,
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &error,
                        &reply,
                        "s", "");
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const char *name;
                const char *contents;

                r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_STRING, &name);
                if (r < 0)
                        return r;

                if (!filter || strv_find(filter, name)) {
                        r = sd_bus_message_peek_type(reply, NULL, &contents);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, contents);
                        if (r < 0)
                                return r;

                        r = bus_print_property(name, reply, all);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                if (all)
                                        printf("%s=[unprintable]\n", name);
                                /* skip what we didn't read */
                                r = sd_bus_message_skip(reply, contents);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return r;
                } else {
                        r = sd_bus_message_skip(reply, "v");
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        return 0;
}

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        sd_id128_t *p = userdata;
        const void *v;
        size_t n;
        int r;

        r = sd_bus_message_read_array(m, SD_BUS_TYPE_BYTE, &v, &n);
        if (r < 0)
                return r;

        if (n == 0)
                *p = SD_ID128_NULL;
        else if (n == 16)
                memcpy((*p).bytes, v, n);
        else
                return -EINVAL;

        return 0;
}

static int map_basic(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char type;
        int r;

        r = sd_bus_message_peek_type(m, &type, NULL);
        if (r < 0)
                return r;

        switch (type) {
        case SD_BUS_TYPE_STRING: {
                const char *s;
                char *str;
                char **p = userdata;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        break;

                if (isempty(s))
                        break;

                str = strdup(s);
                if (!str) {
                        r = -ENOMEM;
                        break;
                }
                free(*p);
                *p = str;

                break;
        }

        case SD_BUS_TYPE_ARRAY: {
               _cleanup_strv_free_ char **l = NULL;
               char ***p = userdata;

                r = bus_message_read_strv_extend(m, &l);
                if (r < 0)
                        break;

                strv_free(*p);
                *p = l;
                l = NULL;

                break;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                unsigned b;
                bool *p = userdata;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        break;

                *p = b;

                break;
        }

        case SD_BUS_TYPE_UINT32: {
                uint64_t u;
                uint32_t *p = userdata;

                r = sd_bus_message_read_basic(m, type, &u);
                if (r < 0)
                        break;

                *p = u;

                break;
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t t;
                uint64_t *p = userdata;

                r = sd_bus_message_read_basic(m, type, &t);
                if (r < 0)
                        break;

                *p = t;

                break;
        }

        default:
                break;
        }

        return r;
}

int bus_map_all_properties(sd_bus *bus,
                           const char *destination,
                           const char *path,
                           const struct bus_properties_map *map,
                           void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(destination);
        assert(path);
        assert(map);

        r = sd_bus_call_method(
                        bus,
                        destination,
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &error,
                        &m,
                        "s", "");
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const struct bus_properties_map *prop;
                const char *member;
                const char *contents;
                void *v;
                unsigned i;

                r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member);
                if (r < 0)
                        return r;

                for (i = 0, prop = NULL; map[i].member; i++)
                        if (streq(map[i].member, member)) {
                                prop = &map[i];
                                break;
                        }

                if (prop) {
                        r = sd_bus_message_peek_type(m, NULL, &contents);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, contents);
                        if (r < 0)
                                return r;

                        v = (uint8_t *)userdata + prop->offset;
                        if (map[i].set)
                                r = prop->set(bus, member, m, &error, v);
                        else
                                r = map_basic(bus, member, m, &error, v);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;
                } else {
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;
        }

        return r;
}

int bus_open_transport(BusTransport transport, const char *host, bool user, sd_bus **bus) {
        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(bus);

        assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
        assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -ENOTSUP);

        switch (transport) {

        case BUS_TRANSPORT_LOCAL:
                if (user)
                        r = sd_bus_default_user(bus);
                else
                        r = sd_bus_default_system(bus);

                break;

        case BUS_TRANSPORT_REMOTE:
                r = sd_bus_open_system_remote(bus, host);
                break;

        case BUS_TRANSPORT_CONTAINER:
                r = sd_bus_open_system_container(bus, host);
                break;

        default:
                assert_not_reached("Hmm, unknown transport type.");
        }

        return r;
}

int bus_open_transport_systemd(BusTransport transport, const char *host, bool user, sd_bus **bus) {
        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(bus);

        assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
        assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -ENOTSUP);

        switch (transport) {

        case BUS_TRANSPORT_LOCAL:
                if (user)
                        r = bus_open_user_systemd(bus);
                else
                        r = bus_open_system_systemd(bus);

                break;

        case BUS_TRANSPORT_REMOTE:
                r = sd_bus_open_system_remote(bus, host);
                break;

        case BUS_TRANSPORT_CONTAINER:
                r = sd_bus_open_system_container(bus, host);
                break;

        default:
                assert_not_reached("Hmm, unknown transport type.");
        }

        return r;
}

int bus_property_get_bool(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int b = *(bool*) userdata;

        return sd_bus_message_append_basic(reply, 'b', &b);
}

#if __SIZEOF_SIZE_T__ != 8
int bus_property_get_size(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t sz = *(size_t*) userdata;

        return sd_bus_message_append_basic(reply, 't', &sz);
}
#endif

#if __SIZEOF_LONG__ != 8
int bus_property_get_long(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int64_t l = *(long*) userdata;

        return sd_bus_message_append_basic(reply, 'x', &l);
}

int bus_property_get_ulong(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t ul = *(unsigned long*) userdata;

        return sd_bus_message_append_basic(reply, 't', &ul);
}
#endif

int bus_log_parse_error(int r) {
        log_error("Failed to parse message: %s", strerror(-r));
        return r;
}

int bus_log_create_error(int r) {
        log_error("Failed to create message: %s", strerror(-r));
        return r;
}

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u) {
        assert(message);
        assert(u);

        u->machine = NULL;

        return sd_bus_message_read(
                        message,
                        "(ssssssouso)",
                        &u->id,
                        &u->description,
                        &u->load_state,
                        &u->active_state,
                        &u->sub_state,
                        &u->following,
                        &u->unit_path,
                        &u->job_id,
                        &u->job_type,
                        &u->job_path);
}

int bus_maybe_reply_error(sd_bus_message *m, int r, sd_bus_error *error) {
        assert(m);

        if (r < 0) {
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        sd_bus_reply_method_errno(m, r, error);

        } else if (sd_bus_error_is_set(error)) {
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        sd_bus_reply_method_error(m, error);
        } else
                return r;

        log_debug("Failed to process message [type=%s sender=%s path=%s interface=%s member=%s signature=%s]: %s",
                  bus_message_type_to_string(m->header->type),
                  strna(m->sender),
                  strna(m->path),
                  strna(m->interface),
                  strna(m->member),
                  strna(m->root_container.signature),
                  bus_error_message(error, r));

        return 1;
}

int bus_append_unit_property_assignment(sd_bus_message *m, const char *assignment) {
        const char *eq, *field;
        int r;

        assert(m);
        assert(assignment);

        eq = strchr(assignment, '=');
        if (!eq) {
                log_error("Not an assignment: %s", assignment);
                return -EINVAL;
        }

        field = strndupa(assignment, eq - assignment);
        eq ++;

        if (streq(field, "CPUQuota")) {

                if (isempty(eq)) {

                        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, "CPUQuotaPerSecUSec");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "v", "t", (usec_t) -1);

                } else if (endswith(eq, "%")) {
                        double percent;

                        if (sscanf(eq, "%lf%%", &percent) != 1 || percent <= 0) {
                                log_error("CPU quota '%s' invalid.", eq);
                                return -EINVAL;
                        }

                        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, "CPUQuotaPerSecUSec");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "v", "t", (usec_t) percent * USEC_PER_SEC / 100);
                } else {
                        log_error("CPU quota needs to be in percent.");
                        return -EINVAL;
                }

                if (r < 0)
                        return bus_log_create_error(r);

                return 0;
        }

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        if (STR_IN_SET(field,
                       "CPUAccounting", "MemoryAccounting", "BlockIOAccounting",
                       "SendSIGHUP", "SendSIGKILL")) {

                r = parse_boolean(eq);
                if (r < 0) {
                        log_error("Failed to parse boolean assignment %s.", assignment);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "b", r);

        } else if (streq(field, "MemoryLimit")) {
                off_t bytes;

                r = parse_size(eq, 1024, &bytes);
                if (r < 0) {
                        log_error("Failed to parse bytes specification %s", assignment);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", (uint64_t) bytes);

        } else if (STR_IN_SET(field, "CPUShares", "BlockIOWeight")) {
                uint64_t u;

                r = safe_atou64(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", u);

        } else if (STR_IN_SET(field, "User", "Group", "DevicePolicy", "KillMode"))
                r = sd_bus_message_append(m, "v", "s", eq);

        else if (streq(field, "DeviceAllow")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(ss)", 0);
                else {
                        const char *path, *rwm, *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                rwm = e+1;
                        } else {
                                path = eq;
                                rwm = "";
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = sd_bus_message_append(m, "v", "a(ss)", 1, path, rwm);
                }

        } else if (STR_IN_SET(field, "BlockIOReadBandwidth", "BlockIOWriteBandwidth")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(st)", 0);
                else {
                        const char *path, *bandwidth, *e;
                        off_t bytes;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                bandwidth = e+1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = parse_size(bandwidth, 1000, &bytes);
                        if (r < 0) {
                                log_error("Failed to parse byte value %s.", bandwidth);
                                return -EINVAL;
                        }

                        r = sd_bus_message_append(m, "v", "a(st)", 1, path, (uint64_t) bytes);
                }

        } else if (streq(field, "BlockIODeviceWeight")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(st)", 0);
                else {
                        const char *path, *weight, *e;
                        uint64_t u;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                weight = e+1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = safe_atou64(weight, &u);
                        if (r < 0) {
                                log_error("Failed to parse %s value %s.", field, weight);
                                return -EINVAL;
                        }
                        r = sd_bus_message_append(m, "v", "a(st)", path, u);
                }

        } else if (rlimit_from_string(field) >= 0) {
                uint64_t rl;

                if (streq(eq, "infinity"))
                        rl = (uint64_t) -1;
                else {
                        r = safe_atou64(eq, &rl);
                        if (r < 0) {
                                log_error("Invalid resource limit: %s", eq);
                                return -EINVAL;
                        }
                }

                r = sd_bus_message_append(m, "v", "t", rl);

        } else if (streq(field, "Nice")) {
                int32_t i;

                r = safe_atoi32(eq, &i);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", i);

        } else if (streq(field, "Environment")) {

                r = sd_bus_message_append(m, "v", "as", 1, eq);

        } else if (streq(field, "KillSignal")) {
                int sig;

                sig = signal_from_string_try_harder(eq);
                if (sig < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", sig);

        } else {
                log_error("Unknown assignment %s.", assignment);
                return -EINVAL;
        }

        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}
