/***
  This file is part of systemd.

  Copyright 2013 Daniel Mack

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/timex.h>
#include <sys/utsname.h>

#include "kdbus.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "event-util.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-message.h"
#include "bus-kernel.h"
#include "socket-util.h"
#include "util.h"
#include "build.h"
#include "strv.h"
#include "sd-id128.h"
#include "async.h"
#include "hashmap.h"
#include "def.h"
#include "unit-name.h"
#include "bus-control.h"
#include "cgroup-util.h"

#define CLIENTS_MAX 1024
#define MATCHES_MAX 1024

typedef struct Match Match;
typedef struct Client Client;
typedef struct Context Context;

struct Match {
        Client *client;
        char *match;
        uint64_t cookie;
        LIST_FIELDS(Match, matches);
};

struct Client {
        Context *context;
        uint64_t id;
        uint64_t next_cookie;
        Hashmap *matches;
        unsigned n_matches;
        char *watch;
};

struct Context {
        sd_bus *bus;
        sd_event *event;
        Hashmap *clients;
};

static void match_free(Match *m) {

        if (!m)
                return;

        if (m->client) {
                Match *first;

                first = hashmap_get(m->client->matches, m->match);
                LIST_REMOVE(matches, first, m);
                if (first)
                        assert_se(hashmap_replace(m->client->matches, first->match, first) >= 0);
                else
                        hashmap_remove(m->client->matches, m->match);

                m->client->n_matches--;
        }

        free(m->match);
        free(m);
}

static int match_new(Client *c, struct bus_match_component *components, unsigned n_components, Match **_m) {
        Match *m, *first;
        int r;

        assert(c);
        assert(_m);

        r = hashmap_ensure_allocated(&c->matches, string_hash_func, string_compare_func);
        if (r < 0)
                return r;

        m = new0(Match, 1);
        if (!m)
                return -ENOMEM;

        m->match = bus_match_to_string(components, n_components);
        if (!m->match) {
                r = -ENOMEM;
                goto fail;
        }

        m->cookie = ++c->next_cookie;

        first = hashmap_get(c->matches, m->match);
        LIST_PREPEND(matches, first, m);
        r = hashmap_replace(c->matches, m->match, first);
        if (r < 0) {
                LIST_REMOVE(matches, first, m);
                goto fail;
        }

        m->client = c;
        c->n_matches++;

        *_m = m;
        m = NULL;

        return 0;

fail:
        match_free(m);
        return r;
}

static int on_name_owner_changed(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error);

static void client_free(Client *c) {
        Match *m;

        if (!c)
                return;

        if (c->context) {
                if (c->watch)
                        sd_bus_remove_match(c->context->bus, c->watch, on_name_owner_changed, c);

                assert_se(hashmap_remove(c->context->clients, &c->id) == c);
        }

        while ((m = hashmap_first(c->matches)))
                match_free(m);

        hashmap_free(c->matches);
        free(c->watch);

        free(c);
}

static int on_name_owner_changed(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Client *c = userdata;

        assert(bus);
        assert(m);

        client_free(c);
        return 0;
}

static int client_acquire(Context *context, uint64_t id, Client **_c) {
        char *watch = NULL;
        Client *c;
        int r;

        assert(context);
        assert(_c);

        c = hashmap_get(context->clients, &id);
        if (c) {
                *_c = c;
                return 0;
        }

        if (hashmap_size(context->clients) >= CLIENTS_MAX)
                return -ENOBUFS;

        r = hashmap_ensure_allocated(&context->clients, uint64_hash_func, uint64_compare_func);
        if (r < 0)
                return r;

        c = new0(Client, 1);
        if (!c)
                return -ENOMEM;

        c->id = id;

        r = hashmap_put(context->clients, &c->id, c);
        if (r < 0)
                goto fail;

        c->context = context;

        if (asprintf(&watch,
                     "type='signal',"
                     "sender='org.freedesktop.DBus',"
                     "path='/org/freedesktop/DBus',"
                     "interface='org.freedesktop.DBus',"
                     "member='NameOwnerChanged',"
                     "arg0=':1.%llu'", (unsigned long long) id) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        r = sd_bus_add_match(context->bus, watch, on_name_owner_changed, c);
        if (r < 0) {
                free(watch);
                goto fail;
        }

        c->watch = watch;

        *_c = c;
        return 0;

fail:
        client_free(c);
        return r;
}

static int driver_add_match(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {

        struct bus_match_component *components = NULL;
        Context *context = userdata;
        unsigned n_components = 0;
        Match *m = NULL;
        Client *c = NULL;
        char *arg0;
        uint64_t id;
        int r;

        assert(bus);
        assert(message);
        assert(context);

        r = sd_bus_message_read(message, "s", &arg0);
        if (r < 0)
                return r;

        r = bus_kernel_parse_unique_name(message->sender, &id);
        if (r < 0)
                return r;

        r = client_acquire(context, id, &c);
        if (r == -ENOBUFS)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Reached limit of %u clients", CLIENTS_MAX);
        if (r < 0)
                return r;

        if (c->n_matches >= MATCHES_MAX) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Reached limit of %u matches per client", MATCHES_MAX);
                goto fail;
        }

        r = bus_match_parse(arg0, &components, &n_components);
        if (r < 0) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_MATCH_RULE_INVALID, "Match rule \"%s\" is not valid", arg0);
                goto fail;
        }

        r = match_new(c, components, n_components, &m);
        if (r < 0)
                goto fail;

        r = bus_add_match_internal_kernel(bus, id, components, n_components, m->cookie);
        if (r < 0)
                goto fail;

        bus_match_parse_free(components, n_components);

        return sd_bus_reply_method_return(message, NULL);

fail:
        bus_match_parse_free(components, n_components);

        match_free(m);

        if (c->n_matches <= 0)
                client_free(c);

        return r;
}

static int driver_remove_match(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {

        struct bus_match_component *components = NULL;
        _cleanup_free_ char *normalized = NULL;
        Context *context = userdata;
        unsigned n_components = 0;
        Client *c = NULL;
        Match *m = NULL;
        char *arg0;
        uint64_t id;
        int r;

        assert(bus);
        assert(message);
        assert(context);

        r = sd_bus_message_read(message, "s", &arg0);
        if (r < 0)
                return r;

        r = bus_kernel_parse_unique_name(message->sender, &id);
        if (r < 0)
                return r;

        c = hashmap_get(context->clients, &id);
        if (!c)
                return sd_bus_error_setf(error, SD_BUS_ERROR_MATCH_RULE_NOT_FOUND, "You have not registered any matches.");

        r = bus_match_parse(arg0, &components, &n_components);
        if (r < 0) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_MATCH_RULE_INVALID, "Match rule \"%s\" is not valid", arg0);
                goto finish;
        }

        normalized = bus_match_to_string(components, n_components);
        if (!normalized) {
                r = -ENOMEM;
                goto finish;
        }

        m = hashmap_get(c->matches, normalized);
        if (!m) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_MATCH_RULE_NOT_FOUND, "Match rule \"%s\" not found.", normalized);
                goto finish;
        }

        bus_remove_match_internal_kernel(bus, id, m->cookie);
        match_free(m);

        r = sd_bus_reply_method_return(message, NULL);

finish:
        bus_match_parse_free(components, n_components);

        if (c->n_matches <= 0)
                client_free(c);

        return r;
}

static int get_creds_by_name(sd_bus *bus, const char *name, uint64_t mask, sd_bus_creds **_creds, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(_creds);

        assert_return(service_name_is_valid(name), -EINVAL);

        r = sd_bus_get_owner(bus, name, mask, &c);
        if (r == -ENOENT || r == -ENXIO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Name %s is currently not owned by anyone.", name);
        if (r < 0)
                return r;

        if ((c->mask & mask) != mask)
                return -ENOTSUP;

        *_creds = c;
        c = NULL;

        return 0;
}


static int get_creds_by_message(sd_bus *bus, sd_bus_message *m, uint64_t mask, sd_bus_creds **_creds, sd_bus_error *error) {
        const char *name;
        int r;

        assert(bus);
        assert(m);
        assert(_creds);

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;

        return get_creds_by_name(bus, name, mask, _creds, error);
}

static int driver_get_security_context(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        int r;

        r = get_creds_by_message(bus, m, SD_BUS_CREDS_SELINUX_CONTEXT, &creds, error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', creds->label, strlen(creds->label));
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_get_pid(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        int r;

        r = get_creds_by_message(bus, m, SD_BUS_CREDS_PID, &creds, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", (uint32_t) creds->pid);
}

static int driver_get_user(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        int r;

        r = get_creds_by_message(bus, m, SD_BUS_CREDS_UID, &creds, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", (uint32_t) creds->uid);
}

static int driver_get_name_owner(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        const char *name;
        int r;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;

        /* Here's a special exception for compatibility with dbus1:
         * the bus name of the driver is owned by itself, not by a
         * unique ID. */
        if (streq(name, "org.freedesktop.DBus"))
                return sd_bus_reply_method_return(m, "s", "org.freedesktop.DBus");

        r = get_creds_by_name(bus, name, SD_BUS_CREDS_UNIQUE_NAME, &creds, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "s", creds->unique_name);
}

static int driver_get_id(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        sd_id128_t server_id;
        char buf[SD_ID128_STRING_MAX];
        int r;

        r = sd_bus_get_server_id(bus, &server_id);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "s", sd_id128_to_string(server_id, buf));
}

static int driver_hello(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return sd_bus_reply_method_return(m, "s", m->sender);
}

static int return_strv(sd_bus *bus, sd_bus_message *m, char **l) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, l);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_list_names(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **names = NULL;
        int r;

        r = sd_bus_list_names(bus, &names, NULL);
        if (r < 0)
                return r;

        /* Let's sort the names list to make it stable */
        strv_sort(names);

        return return_strv(bus, m, names);
}

static int driver_list_activatable_names(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **names = NULL;
        int r;

        r = sd_bus_list_names(bus, NULL, &names);
        if (r < 0)
                return r;

        /* Let's sort the names list to make it stable */
        strv_sort(names);

        return return_strv(bus, m, names);
}

static int driver_list_queued_owners(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct kdbus_cmd_name_list cmd = {};
        struct kdbus_name_list *name_list;
        struct kdbus_cmd_name *name;
        _cleanup_strv_free_ char **owners = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        assert_return(service_name_is_valid(arg0), -EINVAL);

        cmd.flags = KDBUS_NAME_LIST_QUEUED;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_LIST, &cmd);
        if (r < 0)
                return -errno;

        name_list = (struct kdbus_name_list *) ((uint8_t *) bus->kdbus_buffer + cmd.offset);

        KDBUS_ITEM_FOREACH(name, name_list, names) {
                char *n;

                if (name->size <= sizeof(*name))
                        continue;

                if (!streq(name->name, arg0))
                        continue;

                if (asprintf(&n, ":1.%llu", (unsigned long long) name->owner_id) < 0)
                        return -ENOMEM;

                r = strv_push(&owners, n);
                if (r < 0) {
                        free(n);
                        return -ENOMEM;
                }
        }

        r = ioctl(bus->input_fd, KDBUS_CMD_FREE, &cmd.offset);
        if (r < 0)
                return -errno;

        return return_strv(bus, m, owners);
}

static int driver_name_has_owner(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *name;
        int r;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;

        assert_return(service_name_is_valid(name), -EINVAL);

        r = sd_bus_get_owner(bus, name, 0, NULL);
        if (r < 0 && r != -ENOENT && r != -ENXIO)
                return r;

        return sd_bus_reply_method_return(m, "b", r >= 0);
}

static int driver_request_name(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct kdbus_cmd_name *n;
        uint32_t flags;
        size_t size, l;
        uint64_t id;
        const char *name;
        int r;

        r = sd_bus_message_read(m, "su", &name, &flags);
        if (r < 0)
                return r;

        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return((flags & ~(BUS_NAME_ALLOW_REPLACEMENT|BUS_NAME_REPLACE_EXISTING|BUS_NAME_DO_NOT_QUEUE)) == 0, -EINVAL);

        l = strlen(name);
        size = offsetof(struct kdbus_cmd_name, name) + l + 1;
        n = alloca0(size);
        n->size = size;
        memcpy(n->name, name, l+1);
        kdbus_translate_request_name_flags(flags, (uint64_t *) &n->flags);

        /* This function is open-coded because we request the name 'on behalf'
         * of the requesting connection */
        r = bus_kernel_parse_unique_name(m->sender, &id);
        if (r < 0)
                return r;

        n->owner_id = id;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_ACQUIRE, n);
        if (r < 0) {
                if (errno == EEXIST)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_EXISTS);
                if (errno == EALREADY)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_ALREADY_OWNER);

                return -errno;
        }

        if (n->flags & KDBUS_NAME_IN_QUEUE)
                return sd_bus_reply_method_return(m, "u", BUS_NAME_IN_QUEUE);

        return sd_bus_reply_method_return(m, "u", BUS_NAME_PRIMARY_OWNER);
}

static int driver_release_name(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct kdbus_cmd_name *n;
        const char *name;
        size_t l, size;
        uint64_t id;
        int r;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;

        assert_return(service_name_is_valid(name), -EINVAL);

        l = strlen(name);
        size = offsetof(struct kdbus_cmd_name, name) + l + 1;
        n = alloca0(size);
        n->size = size;
        memcpy(n->name, name, l+1);

        /* This function is open-coded because we request the name 'on behalf'
         * of the requesting connection */
        r = bus_kernel_parse_unique_name(m->sender, &id);
        if (r < 0)
                return r;

        n->owner_id = id;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_RELEASE, n);
        if (r < 0) {
                if (errno == ESRCH)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_NON_EXISTENT);
                if (errno == EADDRINUSE)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_NOT_OWNER);
                return -errno;
        }

        return sd_bus_reply_method_return(m, "u", BUS_NAME_RELEASED);
}

static int driver_start_service_by_name(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **t = NULL;
        _cleanup_free_ char *path = NULL;
        uint32_t flags;
        char *name, *u;
        int r;

        r = sd_bus_message_read(m, "su", &name, &flags);
        if (r < 0)
                return r;

        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(flags == 0, -ENOTSUP);

        r = sd_bus_get_owner(bus, name, 0, NULL);
        if (r >= 0)
                return sd_bus_reply_method_return(m, "u", BUS_START_REPLY_ALREADY_RUNNING);
        if (r != -ENOENT)
                return r;

        u = strappenda(name, ".busname");

        path = unit_dbus_path_from_name(u);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Triggers",
                        error,
                        &t);
        if (r < 0)
                return r;

        if (!t || !t[0] || t[1])
                return sd_bus_error_setf(error, SD_BUS_ERROR_SERVICE_UNKNOWN, "Bus name %s not found.", name);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        error,
                        &reply,
                        "ss",
                        t[0],
                        "replace");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", BUS_START_REPLY_SUCCESS);
}

static int driver_update_environment(sd_bus*bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *msg = NULL;
        _cleanup_strv_free_ char **args = NULL;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{ss}");
        if (r < 0)
                return r;

       while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "ss")) > 0) {
                _cleanup_free_ char *s = NULL;
                const char *key;
                const char *value;

                r = sd_bus_message_read(m, "ss", &key, &value);
                if (r < 0)
                        return r;

                s = strjoin(key, "=", value, NULL);
                if (!s)
                        return ENOMEM;

                r  = strv_extend(&args, s);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        if (!args)
                return -EINVAL;

        r = sd_bus_message_new_method_call(
                        bus,
                        &msg,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "SetEnvironment");
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(msg, args);
        if (r < 0)
                return r;

        r = sd_bus_call(bus, msg, 0, NULL, NULL);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, NULL);
}

static int driver_unsupported(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "%s() is not supported", sd_bus_message_get_member(m));
}

static const sd_bus_vtable driver_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("AddMatch", "s", NULL, driver_add_match, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetConnectionSELinuxSecurityContext", "s", "ay", driver_get_security_context, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetConnectionUnixProcessID", "s", "u", driver_get_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetConnectionUnixUser", "s", "u", driver_get_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetId", NULL, "s", driver_get_id, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetNameOwner", "s", "s", driver_get_name_owner, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Hello", NULL, "s", driver_hello, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListActivatableNames", NULL, "as", driver_list_activatable_names, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListNames", NULL, "as", driver_list_names, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListQueuedOwners", "s", "as", driver_list_queued_owners, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("NameHasOwner", "s", "b", driver_name_has_owner, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReleaseName", "s", "u", driver_release_name, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadConfig", NULL, NULL, driver_unsupported, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD("RemoveMatch", "s", NULL, driver_remove_match, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RequestName", "su", "u", driver_request_name, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartServiceByName", "su", "u", driver_start_service_by_name, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UpdateActivationEnvironment", "a{ss}", NULL, driver_update_environment, 0),
        SD_BUS_SIGNAL("NameAcquired", "s", SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_SIGNAL("NameLost", "s", SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_SIGNAL("NameOwnerChanged", "sss", 0),
        SD_BUS_VTABLE_END
};

static int find_object(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **ret_found,
                sd_bus_error *ret_error) {

        /* We support the driver interface on exactly two different
         * paths: the root and the entry point object. This is a bit
         * different from the original dbus-daemon which supported it
         * on any path. */

        if (streq_ptr(path, "/"))
                return 1;

        if (streq_ptr(path, "/org/freedesktop/DBus"))
                return 1;

        return 0;
}

static int node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***ret_nodes,
                sd_bus_error *ret_error) {

        char **l;

        l = strv_new("/", "/org/freedesktop/DBus", NULL);
        if (!l)
                return -ENOMEM;

        *ret_nodes = l;
        return 0;
}

static int connect_bus(Context *c) {
        int r;

        assert(c);

        r = sd_bus_default(&c->bus);
        if (r < 0) {
                log_error("Failed to create bus: %s", strerror(-r));
                return r;
        }

        if (!c->bus->is_kernel) {
                log_error("Not running on kdbus");
                return -EPERM;
        }

        r = sd_bus_add_fallback_vtable(c->bus, "/", "org.freedesktop.DBus", driver_vtable, find_object, c);
        if (r < 0) {
                log_error("Failed to add manager object vtable: %s", strerror(-r));
                return r;
        }

        r = sd_bus_add_node_enumerator(c->bus, "/", node_enumerator, c);
        if (r < 0) {
                log_error("Failed to add node enumerator: %s", strerror(-r));
                return r;
        }

        r = sd_bus_request_name(c->bus, "org.freedesktop.DBus", 0);
        if (r < 0) {
                log_error("Unable to request name: %s", strerror(-r));
                return r;
        }

        r = sd_bus_attach_event(c->bus, c->event, 0);
        if (r < 0) {
                log_error("Error while adding bus to event loop: %s", strerror(-r));
                return r;
        }

        return 0;
}

static bool check_idle(void *userdata) {
        Context *c = userdata;
        assert(c);

        return hashmap_isempty(c->clients);
}

int main(int argc, char *argv[]) {
        Context context = {};
        Client *c;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = sd_event_default(&context.event);
        if (r < 0) {
                log_error("Failed to allocate event loop: %s", strerror(-r));
                goto finish;
        }

        sd_event_set_watchdog(context.event, true);

        r = connect_bus(&context);
        if (r < 0)
                goto finish;

        r = bus_event_loop_with_idle(context.event, context.bus, "org.freedesktop.DBus", DEFAULT_EXIT_USEC, check_idle, &context);
        if (r < 0) {
                log_error("Failed to run event loop: %s", strerror(-r));
                goto finish;
        }

finish:
        while ((c = hashmap_first(context.clients)))
                client_free(c);

        sd_bus_unref(context.bus);
        sd_event_unref(context.event);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
