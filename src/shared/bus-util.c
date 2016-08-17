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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus-protocol.h"
#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-util.h"
#include "def.h"
#include "escape.h"
#include "fd-util.h"
#include "missing.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "rlimit-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "user-util.h"

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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *rep = NULL;
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
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
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
                const char **details,
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
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int authorized = false, challenge = false;
                const char *sender, **k, **v;

                sender = sd_bus_message_get_sender(call);
                if (!sender)
                        return -EBADMSG;

                r = sd_bus_message_new_method_call(
                                call->bus,
                                &request,
                                "org.freedesktop.PolicyKit1",
                                "/org/freedesktop/PolicyKit1/Authority",
                                "org.freedesktop.PolicyKit1.Authority",
                                "CheckAuthorization");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(
                                request,
                                "(sa{sv})s",
                                "system-bus-name", 1, "name", "s", sender,
                                action);
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(request, 'a', "{ss}");
                if (r < 0)
                        return r;

                STRV_FOREACH_PAIR(k, v, details) {
                        r = sd_bus_message_append(request, "{ss}", *k, *v);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_close_container(request);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(request, "us", 0, NULL);
                if (r < 0)
                        return r;

                r = sd_bus_call(call->bus, request, 0, e, &reply);
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
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
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
                const char **details,
                bool interactive,
                uid_t good_user,
                Hashmap **registry,
                sd_bus_error *error) {

#ifdef ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        AsyncPolkitQuery *q;
        const char *sender, **k, **v;
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
                        "(sa{sv})s",
                        "system-bus-name", 1, "name", "s", sender,
                        action);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(pk, 'a', "{ss}");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(k, v, details) {
                r = sd_bus_message_append(pk, "{ss}", *k, *v);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(pk);
        if (r < 0)
                return r;

        r = sd_bus_message_append(pk, "us", !!interactive, NULL);
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

int bus_connect_system_systemd(sd_bus **_bus) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        assert(_bus);

        if (geteuid() != 0)
                return sd_bus_default_system(_bus);

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
                return sd_bus_default_system(_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *_bus = bus;
        bus = NULL;

        return 0;
}

int bus_connect_user_systemd(sd_bus **_bus) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
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
                return sd_bus_default_user(_bus);

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
                return sd_bus_default_user(_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *_bus = bus;
        bus = NULL;

        return 0;
}

#define print_property(name, fmt, ...)                                  \
        do {                                                            \
                if (value)                                              \
                        printf(fmt "\n", __VA_ARGS__);                  \
                else                                                    \
                        printf("%s=" fmt "\n", name, __VA_ARGS__);      \
        } while(0)

int bus_print_property(const char *name, sd_bus_message *property, bool value, bool all) {
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

                        print_property(name, "%s", escaped);
                }

                return 1;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

                r = sd_bus_message_read_basic(property, type, &b);
                if (r < 0)
                        return r;

                print_property(name, "%s", yes_no(b));

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
                                print_property(name, "%s", strempty(t));

                } else if (strstr(name, "USec")) {
                        char timespan[FORMAT_TIMESPAN_MAX];

                        print_property(name, "%s", format_timespan(timespan, sizeof(timespan), u, 0));
                } else
                        print_property(name, "%"PRIu64, u);

                return 1;
        }

        case SD_BUS_TYPE_INT64: {
                int64_t i;

                r = sd_bus_message_read_basic(property, type, &i);
                if (r < 0)
                        return r;

                print_property(name, "%"PRIi64, i);

                return 1;
        }

        case SD_BUS_TYPE_UINT32: {
                uint32_t u;

                r = sd_bus_message_read_basic(property, type, &u);
                if (r < 0)
                        return r;

                if (strstr(name, "UMask") || strstr(name, "Mode"))
                        print_property(name, "%04o", u);
                else
                        print_property(name, "%"PRIu32, u);

                return 1;
        }

        case SD_BUS_TYPE_INT32: {
                int32_t i;

                r = sd_bus_message_read_basic(property, type, &i);
                if (r < 0)
                        return r;

                print_property(name, "%"PRIi32, i);
                return 1;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d;

                r = sd_bus_message_read_basic(property, type, &d);
                if (r < 0)
                        return r;

                print_property(name, "%g", d);
                return 1;
        }

        case SD_BUS_TYPE_ARRAY:
                if (streq(contents, "s")) {
                        bool first = true;
                        const char *str;

                        r = sd_bus_message_enter_container(property, SD_BUS_TYPE_ARRAY, contents);
                        if (r < 0)
                                return r;

                        while ((r = sd_bus_message_read_basic(property, SD_BUS_TYPE_STRING, &str)) > 0) {
                                _cleanup_free_ char *escaped = NULL;

                                if (first && !value)
                                        printf("%s=", name);

                                escaped = xescape(str, "\n ");
                                if (!escaped)
                                        return -ENOMEM;

                                printf("%s%s", first ? "" : " ", escaped);

                                first = false;
                        }
                        if (r < 0)
                                return r;

                        if (first && all && !value)
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

                                if (!value)
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

                                if (!value)
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

int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, char **filter, bool value, bool all) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

                        r = bus_print_property(name, reply, value, all);
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
                char **p = userdata;
                const char *s;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        return r;

                if (isempty(s))
                        s = NULL;

                return free_and_strdup(p, s);
        }

        case SD_BUS_TYPE_ARRAY: {
                _cleanup_strv_free_ char **l = NULL;
                char ***p = userdata;

                r = bus_message_read_strv_extend(m, &l);
                if (r < 0)
                        return r;

                strv_free(*p);
                *p = l;
                l = NULL;
                return 0;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                unsigned b;
                int *p = userdata;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                *p = b;
                return 0;
        }

        case SD_BUS_TYPE_INT32:
        case SD_BUS_TYPE_UINT32: {
                uint32_t u, *p = userdata;

                r = sd_bus_message_read_basic(m, type, &u);
                if (r < 0)
                        return r;

                *p = u;
                return 0;
        }

        case SD_BUS_TYPE_INT64:
        case SD_BUS_TYPE_UINT64: {
                uint64_t t, *p = userdata;

                r = sd_bus_message_read_basic(m, type, &t);
                if (r < 0)
                        return r;

                *p = t;
                return 0;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d, *p = userdata;

                r = sd_bus_message_read_basic(m, type, &d);
                if (r < 0)
                        return r;

                *p = d;
                return 0;
        }}

        return -EOPNOTSUPP;
}

int bus_message_map_all_properties(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                void *userdata) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

int bus_connect_transport(BusTransport transport, const char *host, bool user, sd_bus **bus) {
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

int bus_connect_transport_systemd(BusTransport transport, const char *host, bool user, sd_bus **bus) {
        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(bus);

        assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
        assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -EOPNOTSUPP);

        switch (transport) {

        case BUS_TRANSPORT_LOCAL:
                if (user)
                        r = bus_connect_user_systemd(bus);
                else
                        r = bus_connect_system_systemd(bus);

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

int bus_property_get_rlimit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        struct rlimit *rl;
        uint64_t u;
        rlim_t x;
        const char *is_soft;

        assert(bus);
        assert(reply);
        assert(userdata);

        is_soft = endswith(property, "Soft");
        rl = *(struct rlimit**) userdata;
        if (rl)
                x = is_soft ? rl->rlim_cur : rl->rlim_max;
        else {
                struct rlimit buf = {};
                int z;
                const char *s;

                s = is_soft ? strndupa(property, is_soft - property) : property;

                z = rlimit_from_string(strstr(s, "Limit"));
                assert(z >= 0);

                getrlimit(z, &buf);
                x = is_soft ? buf.rlim_cur : buf.rlim_max;
        }

        /* rlim_t might have different sizes, let's map
         * RLIMIT_INFINITY to (uint64_t) -1, so that it is the same on
         * all archs */
        u = x == RLIM_INFINITY ? (uint64_t) -1 : (uint64_t) x;

        return sd_bus_message_append(reply, "t", u);
}
