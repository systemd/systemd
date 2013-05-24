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

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <stddef.h>
#include <errno.h>

#include "strv.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-control.h"
#include "bus-bloom.h"

int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        int r;

        if (!bus)
                return -EINVAL;
        if (!unique)
                return -EINVAL;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *unique = bus->unique_name;
        return 0;
}

int sd_bus_request_name(sd_bus *bus, const char *name, int flags) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!bus->bus_client)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        if (bus->is_kernel) {
                struct kdbus_cmd_name *n;
                size_t l;

                l = strlen(name);
                n = alloca0(offsetof(struct kdbus_cmd_name, name) + l + 1);
                n->size = offsetof(struct kdbus_cmd_name, name) + l + 1;
                n->flags = flags;
                memcpy(n->name, name, l+1);

#ifdef HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif

                r = ioctl(bus->input_fd, KDBUS_CMD_NAME_ACQUIRE, n);
                if (r < 0)
                        return -errno;

                return n->flags;
        } else {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/",
                                "org.freedesktop.DBus",
                                "RequestName",
                                NULL,
                                &reply,
                                "su",
                                name,
                                flags);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply, "u", &ret);
                if (r < 0)
                        return r;

                return ret;
        }
}

int sd_bus_release_name(sd_bus *bus, const char *name) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!bus->bus_client)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        if (bus->is_kernel) {
                struct kdbus_cmd_name *n;
                size_t l;

                l = strlen(name);
                n = alloca0(offsetof(struct kdbus_cmd_name, name) + l + 1);
                n->size = offsetof(struct kdbus_cmd_name, name) + l + 1;
                memcpy(n->name, name, l+1);

#ifdef HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif
                r = ioctl(bus->input_fd, KDBUS_CMD_NAME_RELEASE, n);
                if (r < 0)
                        return -errno;

                return n->flags;
        } else {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/",
                                "org.freedesktop.DBus",
                                "ReleaseName",
                                NULL,
                                &reply,
                                "s",
                                name);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply, "u", &ret);
                if (r < 0)
                        return r;
        }

        return ret;
}

int sd_bus_list_names(sd_bus *bus, char ***l) {
        _cleanup_bus_message_unref_ sd_bus_message *reply1 = NULL, *reply2 = NULL;
        char **x = NULL;
        int r;

        if (!bus)
                return -EINVAL;
        if (!l)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "ListNames",
                        NULL,
                        &reply1,
                        NULL);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "ListActivatableNames",
                        NULL,
                        &reply2,
                        NULL);
        if (r < 0)
                return r;

        r = bus_message_read_strv_extend(reply1, &x);
        if (r < 0) {
                strv_free(x);
                return r;
        }

        r = bus_message_read_strv_extend(reply2, &x);
        if (r < 0) {
                strv_free(x);
                return r;
        }

        *l = strv_uniq(x);
        return 0;
}

int sd_bus_get_owner(sd_bus *bus, const char *name, char **owner) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *found;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "GetNameOwner",
                        NULL,
                        &reply,
                        "s",
                        name);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "s", &found);
        if (r < 0)
                return r;

        if (owner) {
                char *t;

                t = strdup(found);
                if (!t)
                        return -ENOMEM;

                *owner = t;
        }

        return 0;
}

int sd_bus_get_owner_uid(sd_bus *bus, const char *name, uid_t *uid) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t u;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!uid)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "GetConnectionUnixUser",
                        NULL,
                        &reply,
                        "s",
                        name);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "u", &u);
        if (r < 0)
                return r;

        *uid = (uid_t) u;
        return 0;
}

int sd_bus_get_owner_pid(sd_bus *bus, const char *name, pid_t *pid) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t u;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!pid)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "GetConnectionUnixProcessID",
                        NULL,
                        &reply,
                        "s",
                        name);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "u", &u);
        if (r < 0)
                return r;

        if (u == 0)
                return -EIO;

        *pid = (uid_t) u;
        return 0;
}

int bus_add_match_internal(
                sd_bus *bus,
                const char *match,
                struct bus_match_component *components,
                unsigned n_components,
                uint64_t cookie) {

        int r;

        assert(bus);
        assert(match);

        if (bus->is_kernel) {
                struct kdbus_cmd_match *m;
                struct kdbus_item *item;
                uint64_t bloom[BLOOM_SIZE/8];
                size_t sz;
                const char *sender = NULL;
                size_t sender_length = 0;
                uint64_t src_id = KDBUS_MATCH_SRC_ID_ANY;
                bool using_bloom = false;
                unsigned i;

                zero(bloom);

                sz = offsetof(struct kdbus_cmd_match, items);

                for (i = 0; i < n_components; i++) {
                        struct bus_match_component *c = &components[i];

                        switch (c->type) {

                        case BUS_MATCH_SENDER:
                                r = bus_kernel_parse_unique_name(c->value_str, &src_id);
                                if (r < 0)
                                        return r;

                                if (r > 0) {
                                        sender = c->value_str;
                                        sender_length = strlen(sender);
                                        sz += ALIGN8(offsetof(struct kdbus_item, str) + sender_length + 1);
                                }

                                break;

                        case BUS_MATCH_MESSAGE_TYPE:
                                bloom_add_pair(bloom, "message-type", bus_message_type_to_string(c->value_u8));
                                using_bloom = true;
                                break;

                        case BUS_MATCH_INTERFACE:
                                bloom_add_pair(bloom, "interface", c->value_str);
                                using_bloom = true;
                                break;

                        case BUS_MATCH_MEMBER:
                                bloom_add_pair(bloom, "member", c->value_str);
                                using_bloom = true;
                                break;

                        case BUS_MATCH_PATH:
                                bloom_add_pair(bloom, "path", c->value_str);
                                using_bloom = true;
                                break;

                        case BUS_MATCH_PATH_NAMESPACE:
                                if (!streq(c->value_str, "/")) {
                                        bloom_add_pair(bloom, "path-slash-prefix", c->value_str);
                                        using_bloom = true;
                                }
                                break;

                        case BUS_MATCH_ARG...BUS_MATCH_ARG_LAST: {
                                char buf[sizeof("arg")-1 + 2 + 1];

                                snprintf(buf, sizeof(buf), "arg%u", c->type - BUS_MATCH_ARG);
                                bloom_add_pair(bloom, buf, c->value_str);
                                using_bloom = true;
                                break;
                        }

                        case BUS_MATCH_ARG_PATH...BUS_MATCH_ARG_PATH_LAST: {
                                char buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];

                                snprintf(buf, sizeof(buf), "arg%u-slash-prefix", c->type - BUS_MATCH_ARG_PATH);
                                bloom_add_pair(bloom, buf, c->value_str);
                                using_bloom = true;
                                break;
                        }

                        case BUS_MATCH_ARG_NAMESPACE...BUS_MATCH_ARG_NAMESPACE_LAST: {
                                char buf[sizeof("arg")-1 + 2 + sizeof("-dot-prefix")];

                                snprintf(buf, sizeof(buf), "arg%u-dot-prefix", c->type - BUS_MATCH_ARG_NAMESPACE);
                                bloom_add_pair(bloom, buf, c->value_str);
                                using_bloom = true;
                                break;
                        }

                        case BUS_MATCH_DESTINATION:
                                /* The bloom filter does not include
                                   the destination, since it is only
                                   available for broadcast messages
                                   which do not carry a destination
                                   since they are undirected. */
                                break;

                        case BUS_MATCH_ROOT:
                        case BUS_MATCH_VALUE:
                        case BUS_MATCH_LEAF:
                        case _BUS_MATCH_NODE_TYPE_MAX:
                        case _BUS_MATCH_NODE_TYPE_INVALID:
                                assert_not_reached("Invalid match type?");
                        }
                }

                if (using_bloom)
                        sz += ALIGN8(offsetof(struct kdbus_item, data64) + BLOOM_SIZE);

                m = alloca0(sz);
                m->size = sz;
                m->cookie = cookie;
                m->src_id = src_id;

                item = m->items;

                if (using_bloom) {
                        item->size = offsetof(struct kdbus_item, data64) + BLOOM_SIZE;
                        item->type = KDBUS_MATCH_BLOOM;
                        memcpy(item->data64, bloom, BLOOM_SIZE);

                        item = KDBUS_ITEM_NEXT(item);
                }

                if (sender) {
                        item->size = offsetof(struct kdbus_item, str) + sender_length + 1;
                        item->type = KDBUS_MATCH_SRC_NAME;
                        memcpy(item->str, sender, sender_length + 1);
                }

                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                if (r < 0)
                        return -errno;

        } else {
                return sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/",
                                "org.freedesktop.DBus",
                                "AddMatch",
                                NULL,
                                NULL,
                                "s",
                                match);
        }

        return 0;
}

int bus_remove_match_internal(
                sd_bus *bus,
                const char *match,
                uint64_t cookie) {

        int r;

        assert(bus);
        assert(match);

        if (bus->is_kernel) {
                struct kdbus_cmd_match m;

                zero(m);
                m.size = offsetof(struct kdbus_cmd_match, items);
                m.cookie = cookie;

                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_REMOVE, &m);
                if (r < 0)
                        return -errno;

        } else {
                return sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/",
                                "org.freedesktop.DBus",
                                "RemoveMatch",
                                NULL,
                                NULL,
                                "s",
                                match);
        }

        return 0;
}

int sd_bus_get_owner_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *mid;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        if (streq_ptr(name, bus->unique_name))
                return sd_id128_get_machine(machine);

        r = sd_bus_call_method(bus,
                               name,
                               "/",
                               "org.freedesktop.DBus.Peer",
                               "GetMachineId",
                               NULL,
                               &reply,
                               NULL);

        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "s", &mid);
        if (r < 0)
                return r;

        return sd_id128_from_string(mid, machine);
}
