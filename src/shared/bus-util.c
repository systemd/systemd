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

#include "sd-daemon.h"
#include "sd-event.h"
#include "util.h"
#include "strv.h"
#include "macro.h"
#include "def.h"
#include "path-util.h"
#include "missing.h"
#include "set.h"
#include "signal-util.h"
#include "unit-name.h"

#include "sd-bus.h"
#include "bus-error.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-util.h"
#include "bus-internal.h"

static int name_owner_change_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = userdata;

        assert(m);
        assert(e);

        sd_bus_close(sd_bus_message_get_bus(m));
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

                if (r == 0 && !exiting && idle) {

                        r = sd_bus_try_close(bus);
                        if (r == -EBUSY)
                                continue;

                        /* Fallback for dbus1 connections: we
                         * unregister the name and wait for the
                         * response to come through for it */
                        if (r == -EOPNOTSUPP) {

                                /* Inform the service manager that we
                                 * are going down, so that it will
                                 * queue all further start requests,
                                 * instead of assuming we are already
                                 * running. */
                                sd_notify(false, "STOPPING=1");

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

static int check_good_user(sd_bus_message *m, uid_t good_user) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        uid_t sender_uid;
        int r;

        assert(m);

        if (good_user == UID_INVALID)
                return 0;

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        /* Don't trust augmented credentials for authorization */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_EUID) == 0, -EPERM);

        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0)
                return r;

        return sender_uid == good_user;
}

int bus_test_polkit(
                sd_bus_message *call,
                int capability,
                const char *action,
                uid_t good_user,
                bool *_challenge,
                sd_bus_error *e) {

        int r;

        assert(call);
        assert(action);

        /* Tests non-interactively! */

        r = check_good_user(call, good_user);
        if (r != 0)
                return r;

        r = sd_bus_query_sender_privilege(call, capability);
        if (r < 0)
                return r;
        else if (r > 0)
                return 1;
#ifdef ENABLE_POLKIT
        else {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                int authorized = false, challenge = false;
                const char *sender;

                sender = sd_bus_message_get_sender(call);
                if (!sender)
                        return -EBADMSG;

                r = sd_bus_call_method(
                                call->bus,
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
                                0,
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

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        AsyncPolkitQuery *q = userdata;
        int r;

        assert(reply);
        assert(q);

        q->slot = sd_bus_slot_unref(q->slot);
        q->reply = sd_bus_message_ref(reply);

        r = sd_bus_message_rewind(q->request, true);
        if (r < 0) {
                r = sd_bus_reply_method_errno(q->request, r, NULL);
                goto finish;
        }

        r = q->callback(q->request, q->userdata, &error_buffer);
        r = bus_maybe_reply_error(q->request, r, &error_buffer);

finish:
        async_polkit_query_free(q);

        return r;
}

#endif

int bus_verify_polkit_async(
                sd_bus_message *call,
                int capability,
                const char *action,
                bool interactive,
                uid_t good_user,
                Hashmap **registry,
                sd_bus_error *error) {

#ifdef ENABLE_POLKIT
        _cleanup_bus_message_unref_ sd_bus_message *pk = NULL;
        AsyncPolkitQuery *q;
        const char *sender;
        sd_bus_message_handler_t callback;
        void *userdata;
        int c;
#endif
        int r;

        assert(call);
        assert(action);
        assert(registry);

        r = check_good_user(call, good_user);
        if (r != 0)
                return r;

#ifdef ENABLE_POLKIT
        q = hashmap_get(*registry, call);
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

                if (challenge)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED, "Interactive authentication required.");

                return -EACCES;
        }
#endif

        r = sd_bus_query_sender_privilege(call, capability);
        if (r < 0)
                return r;
        else if (r > 0)
                return 1;

#ifdef ENABLE_POLKIT
        if (sd_bus_get_current_message(call->bus) != call)
                return -EINVAL;

        callback = sd_bus_get_current_handler(call->bus);
        if (!callback)
                return -EINVAL;

        userdata = sd_bus_get_current_userdata(call->bus);

        sender = sd_bus_message_get_sender(call);
        if (!sender)
                return -EBADMSG;

        c = sd_bus_message_get_allow_interactive_authorization(call);
        if (c < 0)
                return c;
        if (c > 0)
                interactive = true;

        r = hashmap_ensure_allocated(registry, NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        call->bus,
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
                        !!interactive,
                        NULL);
        if (r < 0)
                return r;

        q = new0(AsyncPolkitQuery, 1);
        if (!q)
                return -ENOMEM;

        q->request = sd_bus_message_ref(call);
        q->callback = callback;
        q->userdata = userdata;

        r = hashmap_put(*registry, call, q);
        if (r < 0) {
                async_polkit_query_free(q);
                return r;
        }

        q->registry = *registry;

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0) {
                async_polkit_query_free(q);
                return r;
        }

        return 0;
#endif

        return -EACCES;
}

void bus_verify_polkit_async_registry_free(Hashmap *registry) {
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

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = sd_bus_set_address(bus, KERNEL_SYSTEM_BUS_ADDRESS);
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

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        if (asprintf(&bus->address, KERNEL_USER_BUS_ADDRESS_FMT, getuid()) < 0)
                return -ENOMEM;

        bus->bus_client = true;

        r = sd_bus_start(bus);
        if (r >= 0) {
                *_bus = bus;
                bus = NULL;
                return 0;
        }

        bus = sd_bus_unref(bus);

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

                if (all || !isempty(s)) {
                        _cleanup_free_ char *escaped = NULL;

                        escaped = xescape(s, "\n");
                        if (!escaped)
                                return -ENOMEM;

                        printf("%s=%s\n", name, escaped);
                }

                return 1;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

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

        case SD_BUS_TYPE_INT64: {
                int64_t i;

                r = sd_bus_message_read_basic(property, type, &i);
                if (r < 0)
                        return r;

                printf("%s=%lld\n", name, (long long) i);

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
                                _cleanup_free_ char *escaped = NULL;

                                if (first)
                                        printf("%s=", name);

                                escaped = xescape(str, "\n ");
                                if (!escaped)
                                        return -ENOMEM;

                                printf("%s%s", first ? "" : " ", escaped);

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
                char **p = userdata;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        break;

                if (isempty(s))
                        break;

                r = free_and_strdup(p, s);
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

int bus_message_map_all_properties(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(m);
        assert(map);

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
                                r = prop->set(sd_bus_message_get_bus(m), member, m, &error, v);
                        else
                                r = map_basic(sd_bus_message_get_bus(m), member, m, &error, v);
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
        if (r < 0)
                return r;

        return sd_bus_message_exit_container(m);
}

int bus_message_map_properties_changed(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                void *userdata) {

        const char *member;
        int r, invalidated, i;

        assert(m);
        assert(map);

        r = bus_message_map_all_properties(m, map, userdata);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return r;

        invalidated = 0;
        while ((r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member)) > 0)
                for (i = 0; map[i].member; i++)
                        if (streq(map[i].member, member)) {
                                ++invalidated;
                                break;
                        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return invalidated;
}

int bus_map_all_properties(
                sd_bus *bus,
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

        return bus_message_map_all_properties(m, map, userdata);
}

int bus_open_transport(BusTransport transport, const char *host, bool user, sd_bus **bus) {
        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(bus);

        assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
        assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -EOPNOTSUPP);

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

        case BUS_TRANSPORT_MACHINE:
                r = sd_bus_open_system_machine(bus, host);
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
        assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -EOPNOTSUPP);

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

        case BUS_TRANSPORT_MACHINE:
                r = sd_bus_open_system_machine(bus, host);
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
        return log_error_errno(r, "Failed to parse bus message: %m");
}

int bus_log_create_error(int r) {
        return log_error_errno(r, "Failed to create bus message: %m");
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

                        r = sd_bus_message_append(m, "v", "t", USEC_INFINITY);

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
                       "SendSIGHUP", "SendSIGKILL", "WakeSystem", "DefaultDependencies")) {

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

        } else if (streq(field, "AccuracySec")) {
                usec_t u;

                r = parse_sec(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", u);

        } else {
                log_error("Unknown assignment %s.", assignment);
                return -EINVAL;
        }

        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

typedef struct BusWaitForJobs {
        sd_bus *bus;
        Set *jobs;

        char *name;
        char *result;

        sd_bus_slot *slot_job_removed;
        sd_bus_slot *slot_disconnected;
} BusWaitForJobs;

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert(m);

        log_error("Warning! D-Bus connection terminated.");
        sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *path, *unit, *result;
        BusWaitForJobs *d = userdata;
        uint32_t id;
        char *found;
        int r;

        assert(m);
        assert(d);

        r = sd_bus_message_read(m, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        found = set_remove(d->jobs, (char*) path);
        if (!found)
                return 0;

        free(found);

        if (!isempty(result))
                d->result = strdup(result);

        if (!isempty(unit))
                d->name = strdup(unit);

        return 0;
}

void bus_wait_for_jobs_free(BusWaitForJobs *d) {
        if (!d)
                return;

        set_free_free(d->jobs);

        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_slot_unref(d->slot_job_removed);

        sd_bus_unref(d->bus);

        free(d->name);
        free(d->result);

        free(d);
}

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new0(BusWaitForJobs, 1);
        if (!d)
                return -ENOMEM;

        d->bus = sd_bus_ref(bus);

        /* When we are a bus client we match by sender. Direct
         * connections OTOH have no initialized sender field, and
         * hence we ignore the sender then */
        r = sd_bus_add_match(
                        bus,
                        &d->slot_job_removed,
                        bus->bus_client ?
                        "type='signal',"
                        "sender='org.freedesktop.systemd1',"
                        "interface='org.freedesktop.systemd1.Manager',"
                        "member='JobRemoved',"
                        "path='/org/freedesktop/systemd1'" :
                        "type='signal',"
                        "interface='org.freedesktop.systemd1.Manager',"
                        "member='JobRemoved',"
                        "path='/org/freedesktop/systemd1'",
                        match_job_removed, d);
        if (r < 0)
                return r;

        r = sd_bus_add_match(
                        bus,
                        &d->slot_disconnected,
                        "type='signal',"
                        "sender='org.freedesktop.DBus.Local',"
                        "interface='org.freedesktop.DBus.Local',"
                        "member='Disconnected'",
                        match_disconnected, d);
        if (r < 0)
                return r;

        *ret = d;
        d = NULL;

        return 0;
}

static int bus_process_wait(sd_bus *bus) {
        int r;

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

static int bus_job_get_service_result(BusWaitForJobs *d, char **result) {
        _cleanup_free_ char *dbus_path = NULL;

        assert(d);
        assert(d->name);
        assert(result);

        dbus_path = unit_dbus_path_from_name(d->name);
        if (!dbus_path)
                return -ENOMEM;

        return sd_bus_get_property_string(d->bus,
                                          "org.freedesktop.systemd1",
                                          dbus_path,
                                          "org.freedesktop.systemd1.Service",
                                          "Result",
                                          NULL,
                                          result);
}

static const struct {
        const char *result, *explanation;
} explanations [] = {
        { "resources",   "a configured resource limit was exceeded" },
        { "timeout",     "a timeout was exceeded" },
        { "exit-code",   "the control process exited with error code" },
        { "signal",      "a fatal signal was delivered to the control process" },
        { "core-dump",   "a fatal signal was delivered causing the control process to dump core" },
        { "watchdog",    "the service failed to send watchdog ping" },
        { "start-limit", "start of the service was attempted too often" }
};

static void log_job_error_with_service_result(const char* service, const char *result) {
        _cleanup_free_ char *service_shell_quoted = NULL;

        assert(service);

        service_shell_quoted = shell_maybe_quote(service);

        if (!isempty(result)) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(explanations); ++i)
                        if (streq(result, explanations[i].result))
                                break;

                if (i < ELEMENTSOF(explanations)) {
                        log_error("Job for %s failed because %s. See \"systemctl status %s\" and \"journalctl -xe\" for details.\n",
                                  service,
                                  explanations[i].explanation,
                                  strna(service_shell_quoted));

                        goto finish;
                }
        }

        log_error("Job for %s failed. See \"systemctl status %s\" and \"journalctl -xe\" for details.\n",
                  service,
                  strna(service_shell_quoted));

finish:
        /* For some results maybe additional explanation is required */
        if (streq_ptr(result, "start-limit"))
                log_info("To force a start use \"systemctl reset-failed %1$s\" followed by \"systemctl start %1$s\" again.",
                         strna(service_shell_quoted));
}

static int check_wait_response(BusWaitForJobs *d, bool quiet) {
        int r = 0;

        assert(d->result);

        if (!quiet) {
                if (streq(d->result, "canceled"))
                        log_error("Job for %s canceled.", strna(d->name));
                else if (streq(d->result, "timeout"))
                        log_error("Job for %s timed out.", strna(d->name));
                else if (streq(d->result, "dependency"))
                        log_error("A dependency job for %s failed. See 'journalctl -xe' for details.", strna(d->name));
                else if (streq(d->result, "invalid"))
                        log_error("Job for %s invalid.", strna(d->name));
                else if (streq(d->result, "assert"))
                        log_error("Assertion failed on job for %s.", strna(d->name));
                else if (streq(d->result, "unsupported"))
                        log_error("Operation on or unit type of %s not supported on this system.", strna(d->name));
                else if (!streq(d->result, "done") && !streq(d->result, "skipped")) {
                        if (d->name) {
                                int q;
                                _cleanup_free_ char *result = NULL;

                                q = bus_job_get_service_result(d, &result);
                                if (q < 0)
                                        log_debug_errno(q, "Failed to get Result property of service %s: %m", d->name);

                                log_job_error_with_service_result(d->name, result);
                        } else
                                log_error("Job failed. See \"journalctl -xe\" for details.");
                }
        }

        if (streq(d->result, "canceled"))
                r = -ECANCELED;
        else if (streq(d->result, "timeout"))
                r = -ETIME;
        else if (streq(d->result, "dependency"))
                r = -EIO;
        else if (streq(d->result, "invalid"))
                r = -ENOEXEC;
        else if (streq(d->result, "assert"))
                r = -EPROTO;
        else if (streq(d->result, "unsupported"))
                r = -EOPNOTSUPP;
        else if (!streq(d->result, "done") && !streq(d->result, "skipped"))
                r = -EIO;

        return r;
}

int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet) {
        int r = 0;

        assert(d);

        while (!set_isempty(d->jobs)) {
                int q;

                q = bus_process_wait(d->bus);
                if (q < 0)
                        return log_error_errno(q, "Failed to wait for response: %m");

                if (d->result) {
                        q = check_wait_response(d, quiet);
                        /* Return the first error as it is most likely to be
                         * meaningful. */
                        if (q < 0 && r == 0)
                                r = q;

                        log_debug_errno(q, "Got result %s/%m for job %s", strna(d->result), strna(d->name));
                }

                free(d->name);
                d->name = NULL;

                free(d->result);
                d->result = NULL;
        }

        return r;
}

int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path) {
        int r;

        assert(d);

        r = set_ensure_allocated(&d->jobs, &string_hash_ops);
        if (r < 0)
                return r;

        return set_put_strdup(d->jobs, path);
}

int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet) {
        int r;

        r = bus_wait_for_jobs_add(d, path);
        if (r < 0)
                return log_oom();

        return bus_wait_for_jobs(d, quiet);
}

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet, UnitFileChange **changes, unsigned *n_changes) {
        const char *type, *path, *source;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(m, "(sss)", &type, &path, &source)) > 0) {
                if (!quiet) {
                        if (streq(type, "symlink"))
                                log_info("Created symlink from %s to %s.", path, source);
                        else
                                log_info("Removed symlink %s.", path);
                }

                r = unit_file_changes_add(changes, n_changes, streq(type, "symlink") ? UNIT_FILE_SYMLINK : UNIT_FILE_UNLINK, path, source);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

/**
 * bus_path_encode_unique() - encode unique object path
 * @b: bus connection or NULL
 * @prefix: object path prefix
 * @sender_id: unique-name of client, or NULL
 * @external_id: external ID to be chosen by client, or NULL
 * @ret_path: storage for encoded object path pointer
 *
 * Whenever we provide a bus API that allows clients to create and manage
 * server-side objects, we need to provide a unique name for these objects. If
 * we let the server choose the name, we suffer from a race condition: If a
 * client creates an object asynchronously, it cannot destroy that object until
 * it received the method reply. It cannot know the name of the new object,
 * thus, it cannot destroy it. Furthermore, it enforces a round-trip.
 *
 * Therefore, many APIs allow the client to choose the unique name for newly
 * created objects. There're two problems to solve, though:
 *    1) Object names are usually defined via dbus object paths, which are
 *       usually globally namespaced. Therefore, multiple clients must be able
 *       to choose unique object names without interference.
 *    2) If multiple libraries share the same bus connection, they must be
 *       able to choose unique object names without interference.
 * The first problem is solved easily by prefixing a name with the
 * unique-bus-name of a connection. The server side must enforce this and
 * reject any other name. The second problem is solved by providing unique
 * suffixes from within sd-bus.
 *
 * This helper allows clients to create unique object-paths. It uses the
 * template '/prefix/sender_id/external_id' and returns the new path in
 * @ret_path (must be freed by the caller).
 * If @sender_id is NULL, the unique-name of @b is used. If @external_id is
 * NULL, this function allocates a unique suffix via @b (by requesting a new
 * cookie). If both @sender_id and @external_id are given, @b can be passed as
 * NULL.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int bus_path_encode_unique(sd_bus *b, const char *prefix, const char *sender_id, const char *external_id, char **ret_path) {
        _cleanup_free_ char *sender_label = NULL, *external_label = NULL;
        char external_buf[DECIMAL_STR_MAX(uint64_t)], *p;
        int r;

        assert_return(b || (sender_id && external_id), -EINVAL);
        assert_return(object_path_is_valid(prefix), -EINVAL);
        assert_return(ret_path, -EINVAL);

        if (!sender_id) {
                r = sd_bus_get_unique_name(b, &sender_id);
                if (r < 0)
                        return r;
        }

        if (!external_id) {
                xsprintf(external_buf, "%"PRIu64, ++b->cookie);
                external_id = external_buf;
        }

        sender_label = bus_label_escape(sender_id);
        if (!sender_label)
                return -ENOMEM;

        external_label = bus_label_escape(external_id);
        if (!external_label)
                return -ENOMEM;

        p = strjoin(prefix, "/", sender_label, "/", external_label, NULL);
        if (!p)
                return -ENOMEM;

        *ret_path = p;
        return 0;
}

/**
 * bus_path_decode_unique() - decode unique object path
 * @path: object path to decode
 * @prefix: object path prefix
 * @ret_sender: output parameter for sender-id label
 * @ret_external: output parameter for external-id label
 *
 * This does the reverse of bus_path_encode_unique() (see its description for
 * details). Both trailing labels, sender-id and external-id, are unescaped and
 * returned in the given output parameters (the caller must free them).
 *
 * Note that this function returns 0 if the path does not match the template
 * (see bus_path_encode_unique()), 1 if it matched.
 *
 * Returns: Negative error code on failure, 0 if the given object path does not
 *          match the template (return parameters are set to NULL), 1 if it was
 *          parsed successfully (return parameters contain allocated labels).
 */
int bus_path_decode_unique(const char *path, const char *prefix, char **ret_sender, char **ret_external) {
        const char *p, *q;
        char *sender, *external;

        assert(object_path_is_valid(path));
        assert(object_path_is_valid(prefix));
        assert(ret_sender);
        assert(ret_external);

        p = object_path_startswith(path, prefix);
        if (!p) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        q = strchr(p, '/');
        if (!q) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        sender = bus_label_unescape_n(p, q - p);
        external = bus_label_unescape(q + 1);
        if (!sender || !external) {
                free(sender);
                free(external);
                return -ENOMEM;
        }

        *ret_sender = sender;
        *ret_external = external;
        return 1;
}

bool is_kdbus_wanted(void) {
        _cleanup_free_ char *value = NULL;
#ifdef ENABLE_KDBUS
        const bool configured = true;
#else
        const bool configured = false;
#endif

        int r;

        if (get_proc_cmdline_key("kdbus", NULL) > 0)
                return true;

        r = get_proc_cmdline_key("kdbus=", &value);
        if (r <= 0)
                return configured;

        return parse_boolean(value) == 1;
}

bool is_kdbus_available(void) {
        _cleanup_close_ int fd = -1;
        struct kdbus_cmd cmd = { .size = sizeof(cmd), .flags = KDBUS_FLAG_NEGOTIATE };

        if (!is_kdbus_wanted())
                return false;

        fd = open("/sys/fs/kdbus/control", O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
        if (fd < 0)
                return false;

        return ioctl(fd, KDBUS_CMD_BUS_MAKE, &cmd) >= 0;
}
