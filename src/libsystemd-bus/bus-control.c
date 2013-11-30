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
#include "bus-util.h"

_public_ int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(unique, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *unique = bus->unique_name;
        return 0;
}

_public_ int sd_bus_request_name(sd_bus *bus, const char *name, int flags) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(bus->bus_client, -EINVAL);
        assert_return(BUS_IS_OPEN(bus->state), -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->is_kernel) {
                struct kdbus_cmd_name *n;
                size_t l;

                l = strlen(name);
                n = alloca0(offsetof(struct kdbus_cmd_name, name) + l + 1);
                n->size = offsetof(struct kdbus_cmd_name, name) + l + 1;
                kdbus_translate_request_name_flags(flags, (uint64_t *) &n->flags);
                memcpy(n->name, name, l+1);

#ifdef HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif

                r = ioctl(bus->input_fd, KDBUS_CMD_NAME_ACQUIRE, n);
                if (r < 0) {
                        if (errno == -EALREADY)
                                return SD_BUS_NAME_ALREADY_OWNER;

                        if (errno == -EEXIST)
                                return SD_BUS_NAME_EXISTS;

                        return -errno;
                }

                if (n->flags & KDBUS_NAME_IN_QUEUE)
                        return SD_BUS_NAME_IN_QUEUE;

                return SD_BUS_NAME_PRIMARY_OWNER;
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

_public_ int sd_bus_release_name(sd_bus *bus, const char *name) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(bus->bus_client, -EINVAL);
        assert_return(BUS_IS_OPEN(bus->state), -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

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

_public_ int sd_bus_list_names(sd_bus *bus, char ***l) {
        _cleanup_bus_message_unref_ sd_bus_message *reply1 = NULL, *reply2 = NULL;
        char **x = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(l, -EINVAL);
        assert_return(BUS_IS_OPEN(bus->state), -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->is_kernel) {
                _cleanup_free_ struct kdbus_cmd_name_list *cmd = NULL;
                struct kdbus_name_list *name_list;
                struct kdbus_cmd_name *name;

                cmd = malloc0(sizeof(struct kdbus_cmd_name_list *));
                if (!cmd)
                        return -ENOMEM;

                cmd->flags = KDBUS_NAME_LIST_UNIQUE_NAMES;

                r = ioctl(sd_bus_get_fd(bus), KDBUS_CMD_NAME_LIST, cmd);
                if (r < 0)
                        return -errno;

                name_list = (struct kdbus_name_list *) ((uint8_t *) bus->kdbus_buffer + cmd->offset);

                KDBUS_PART_FOREACH(name, name_list, names) {
                        char *n;

                        if (name->size > sizeof(*name))
                                n = name->name;
                        else
                                asprintf(&n, ":1.%llu", (unsigned long long) name->id);

                        r = strv_extend(&x, n);
                        if (r < 0)
                                return -ENOMEM;
                }

                r = ioctl(sd_bus_get_fd(bus), KDBUS_CMD_FREE, &cmd->offset);
                if (r < 0)
                        return -errno;

                *l = x;
        } else {
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
        }

        return 0;
}

static int bus_get_owner_dbus(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        _cleanup_bus_message_unref_ sd_bus_message *reply_unique = NULL, *reply = NULL;
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        const char *unique = NULL;
        pid_t pid = 0;
        int r;

        /* Only query the owner if the caller wants to know it or if
         * the caller just wants to check whether a name exists */
        if ((mask & SD_BUS_CREDS_UNIQUE_NAME) || mask == 0) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/",
                                "org.freedesktop.DBus",
                                "GetNameOwner",
                                NULL,
                                &reply_unique,
                                "s",
                                name);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply_unique, "s", &unique);
                if (r < 0)
                        return r;
        }

        if (mask != 0) {
                c = bus_creds_new();
                if (!c)
                        return -ENOMEM;

                if ((mask & SD_BUS_CREDS_UNIQUE_NAME) && unique) {
                        c->unique_name = strdup(unique);
                        if (!c->unique_name)
                                return -ENOMEM;

                        c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
                }

                if (mask & (SD_BUS_CREDS_PID|SD_BUS_CREDS_PID_STARTTIME|SD_BUS_CREDS_GID|
                            SD_BUS_CREDS_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                            SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                            SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                            SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID)) {
                        uint32_t u;

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/",
                                        "org.freedesktop.DBus",
                                        "GetConnectionUnixProcessID",
                                        NULL,
                                        &reply,
                                        "s",
                                        unique ? unique : name);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_read(reply, "u", &u);
                        if (r < 0)
                                return r;

                        pid = u;
                        if (mask & SD_BUS_CREDS_PID) {
                                c->pid = u;
                                c->mask |= SD_BUS_CREDS_PID;
                        }

                        reply = sd_bus_message_unref(reply);
                }

                if (mask & SD_BUS_CREDS_UID) {
                        uint32_t u;

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/",
                                        "org.freedesktop.DBus",
                                        "GetConnectionUnixUser",
                                        NULL,
                                        &reply,
                                        "s",
                                        unique ? unique : name);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_read(reply, "u", &u);
                        if (r < 0)
                                return r;

                        c->uid = u;
                        c->mask |= SD_BUS_CREDS_UID;

                        reply = sd_bus_message_unref(reply);
                }

                if (mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                        const void *p;
                        size_t sz;

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/",
                                        "org.freedesktop.DBus",
                                        "GetConnectionSELinuxSecurityContext",
                                        NULL,
                                        &reply,
                                        "s",
                                        unique ? unique : name);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_read_array(reply, 'y', &p, &sz);
                        if (r < 0)
                                return r;

                        c->label = strndup(p, sz);
                        if (!c->label)
                                return -ENOMEM;

                        c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
                }

                r = bus_creds_add_more(c, mask, pid, 0);
                if (r < 0)
                        return r;
        }

        if (creds) {
                *creds = c;
                c = NULL;
        }

        return 0;
}

static int bus_get_owner_kdbus(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        struct kdbus_cmd_name_info *cmd;
        struct kdbus_name_info *name_info;
        struct kdbus_item *item;
        size_t size;
        uint64_t m, id;
        int r;

        r = bus_kernel_parse_unique_name(name, &id);
        if (r < 0)
                return r;
        if (r > 0) {
                size = offsetof(struct kdbus_cmd_name_info, name);
                cmd = alloca0(size);
                cmd->id = id;
        } else {
                size = offsetof(struct kdbus_cmd_name_info, name) + strlen(name) + 1;
                cmd = alloca0(size);
                strcpy(cmd->name, name);
        }

        cmd->size = size;

        r = kdbus_translate_attach_flags(mask, (uint64_t*) &cmd->attach_flags);
        if (r < 0)
                return r;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_INFO, cmd);
        if (r < 0)
                return -errno;

        name_info = (struct kdbus_name_info *) ((uint8_t *) bus->kdbus_buffer + cmd->offset);

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        if (mask & SD_BUS_CREDS_UNIQUE_NAME) {
                if (asprintf(&c->unique_name, ":1.%llu", (unsigned long long) name_info->id) < 0)
                        return -ENOMEM;

                c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
        }

        KDBUS_PART_FOREACH(item, name_info, items) {

                switch (item->type) {

                case KDBUS_ITEM_CREDS:
                        m = (SD_BUS_CREDS_UID | SD_BUS_CREDS_GID | SD_BUS_CREDS_PID |
                             SD_BUS_CREDS_TID | SD_BUS_CREDS_PID_STARTTIME) & mask;

                        if (m) {
                                c->uid = item->creds.uid;
                                c->pid = item->creds.pid;
                                c->gid = item->creds.gid;
                                c->tid = item->creds.tid;
                                c->pid_starttime = item->creds.starttime;
                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_PID_COMM:
                        if (mask & SD_BUS_CREDS_COMM) {
                                c->comm = strdup(item->str);
                                if (!c->comm) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_COMM;
                        }
                        break;

                case KDBUS_ITEM_TID_COMM:
                        if (mask & SD_BUS_CREDS_TID_COMM) {
                                c->tid_comm = strdup(item->str);
                                if (!c->tid_comm) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_TID_COMM;
                        }
                        break;

                case KDBUS_ITEM_EXE:
                        if (mask & SD_BUS_CREDS_EXE) {
                                c->exe = strdup(item->str);
                                if (!c->exe) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_EXE;
                        }
                        break;

                case KDBUS_ITEM_CMDLINE:
                        if (mask & SD_BUS_CREDS_CMDLINE) {
                                c->cmdline_size = item->size - KDBUS_PART_HEADER_SIZE;
                                c->cmdline = memdup(item->data, c->cmdline_size);
                                if (!c->cmdline) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_CMDLINE;
                        }
                        break;

                case KDBUS_ITEM_CGROUP:
                        m = (SD_BUS_CREDS_CGROUP | SD_BUS_CREDS_UNIT |
                             SD_BUS_CREDS_USER_UNIT | SD_BUS_CREDS_SLICE |
                             SD_BUS_CREDS_SESSION | SD_BUS_CREDS_OWNER_UID) & mask;

                        if (m) {
                                c->cgroup = strdup(item->str);
                                if (!c->cgroup) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_CAPS:
                        m = (SD_BUS_CREDS_EFFECTIVE_CAPS | SD_BUS_CREDS_PERMITTED_CAPS |
                             SD_BUS_CREDS_INHERITABLE_CAPS | SD_BUS_CREDS_BOUNDING_CAPS) & mask;

                        if (m) {
                                c->capability_size = item->size - KDBUS_PART_HEADER_SIZE;
                                c->capability = memdup(item->data, c->capability_size);
                                if (!c->capability) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_SECLABEL:
                        if (mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                                c->label = strdup(item->str);
                                if (!c->label) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
                        }
                        break;

                case KDBUS_ITEM_AUDIT:
                        m = (SD_BUS_CREDS_AUDIT_SESSION_ID | SD_BUS_CREDS_AUDIT_LOGIN_UID) & mask;

                        if (m) {
                                c->audit_session_id = item->audit.sessionid;
                                c->audit_login_uid = item->audit.loginuid;
                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_NAMES:
                        if (mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) {
                                c->well_known_names_size = item->size - KDBUS_PART_HEADER_SIZE;
                                c->well_known_names = memdup(item->data, c->well_known_names_size);
                                if (!c->well_known_names) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES;
                        }
                        break;
                }
        }

        if (creds) {
                *creds = c;
                c = NULL;
        }

        r = 0;

fail:
        ioctl(bus->input_fd, KDBUS_CMD_FREE, &cmd->offset);
        return r;
}

_public_ int sd_bus_get_owner(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(mask <= _SD_BUS_CREDS_MAX, -ENOTSUP);
        assert_return(mask == 0 || creds, -EINVAL);
        assert_return(BUS_IS_OPEN(bus->state), -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->is_kernel)
                return bus_get_owner_kdbus(bus, name, mask, creds);
        else
                return bus_get_owner_dbus(bus, name, mask, creds);
}

static int add_name_change_match(sd_bus *bus,
                                 uint64_t cookie,
                                 const char *name,
                                 const char *old_owner,
                                 const char *new_owner) {

        uint64_t name_id = 0, old_owner_id = 0, new_owner_id = 0;
        int is_name_id = -1, r;
        struct kdbus_item *item;

        assert(bus);

        /* If we encounter a match that could match against
         * NameOwnerChanged messages, then we need to create
         * KDBUS_MATCH_NAME_{ADD,REMOVE,CHANGE} and
         * KDBUS_MATCH_ID_{ADD,REMOVE} matches for it, possibly
         * multiple if the match is underspecified.
         *
         * The NameOwnerChanged signals take three parameters with
         * unique or well-known names, but only some forms actually
         * exist:
         *
         * WELLKNOWN, "", UNIQUE       → KDBUS_MATCH_NAME_ADD
         * WELLKNOWN, UNIQUE, ""       → KDBUS_MATCH_NAME_REMOVE
         * WELLKNOWN, UNIQUE, UNIQUE   → KDBUS_MATCH_NAME_CHANGE
         * UNIQUE, "", UNIQUE          → KDBUS_MATCH_ID_ADD
         * UNIQUE, UNIQUE, ""          → KDBUS_MATCH_ID_REMOVE
         *
         * For the latter two the two unique names must be identical.
         *
         * */

        if (name) {
                is_name_id = bus_kernel_parse_unique_name(name, &name_id);
                if (is_name_id < 0)
                        return 0;
        }

        if (old_owner) {
                r = bus_kernel_parse_unique_name(old_owner, &old_owner_id);
                if (r < 0)
                        return 0;
                if (r == 0)
                        return 0;
                if (is_name_id > 0 && old_owner_id != name_id)
                        return 0;
        }

        if (new_owner) {
                r = bus_kernel_parse_unique_name(new_owner, &new_owner_id);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;
                if (is_name_id > 0 && new_owner_id != name_id)
                        return 0;
        }

        if (is_name_id <= 0) {
                size_t sz, l;

                /* If the name argument is missing or is a well-known
                 * name, then add KDBUS_MATCH_NAME_{ADD,REMOVE,CHANGE}
                 * matches for it */

                l = name ? strlen(name) : 0;

                sz = ALIGN8(offsetof(struct kdbus_cmd_match, items) +
                            offsetof(struct kdbus_item, name_change) +
                            offsetof(struct kdbus_notify_name_change, name) +
                            l+1);

                {
                        union {
                                uint8_t buffer[sz];
                                struct kdbus_cmd_match match;
                        } m;

                        memzero(&m, sz);

                        m.match.size = sz;
                        m.match.cookie = cookie;
                        m.match.src_id = KDBUS_SRC_ID_KERNEL;

                        item = m.match.items;
                        item->size =
                                offsetof(struct kdbus_item, name_change) +
                                offsetof(struct kdbus_notify_name_change, name) +
                                l+1;

                        item->name_change.old_id = old_owner_id;
                        item->name_change.new_id = new_owner_id;

                        if (name)
                                strcpy(item->name_change.name, name);

                        /* If the old name is unset or empty, then
                         * this can match against added names */
                        if (!old_owner || old_owner[0] == 0) {
                                item->type = KDBUS_MATCH_NAME_ADD;

                                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                                if (r < 0)
                                        return -errno;
                        }

                        /* If the new name is unset or empty, then
                         * this can match against removed names */
                        if (!new_owner || new_owner[0] == 0) {
                                item->type = KDBUS_MATCH_NAME_REMOVE;

                                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                                if (r < 0)
                                        return -errno;
                        }

                        /* If the neither name is explicitly set to
                         * the empty string, then this can match
                         * agains changed names */
                        if (!(old_owner && old_owner[0] == 0) &&
                            !(new_owner && new_owner[0] == 0)) {
                                item->type = KDBUS_MATCH_NAME_CHANGE;

                                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                                if (r < 0)
                                        return -errno;
                        }
                }
        }

        if (is_name_id != 0) {
                uint64_t sz =
                        ALIGN8(offsetof(struct kdbus_cmd_match, items) +
                               offsetof(struct kdbus_item, id_change) +
                               sizeof(struct kdbus_notify_id_change));
                union {
                        uint8_t buffer[sz];
                        struct kdbus_cmd_match match;
                } m;

                /* If the name argument is missing or is a unique
                 * name, then add KDBUS_MATCH_ID_{ADD,REMOVE} matches
                 * for it */

                memzero(&m, sz);

                m.match.size = sz;
                m.match.cookie = cookie;
                m.match.src_id = KDBUS_SRC_ID_KERNEL;

                item = m.match.items;
                item->size = offsetof(struct kdbus_item, id_change) + sizeof(struct kdbus_notify_id_change);
                item->id_change.id = name_id;

                /* If the old name is unset or empty, then this can
                 * match against added ids */
                if (!old_owner || old_owner[0] == 0) {
                        item->type = KDBUS_MATCH_ID_ADD;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* If thew new name is unset or empty, then this can
                match against removed ids */
                if (!new_owner || new_owner[0] == 0) {
                        item->type = KDBUS_MATCH_ID_REMOVE;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }
        }

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
                bool matches_name_change = true;
                const char *name_change_arg[3] = {};

                zero(bloom);

                sz = offsetof(struct kdbus_cmd_match, items);

                for (i = 0; i < n_components; i++) {
                        struct bus_match_component *c = &components[i];

                        switch (c->type) {

                        case BUS_MATCH_SENDER:
                                if (!streq(c->value_str, "org.freedesktop.DBus"))
                                        matches_name_change = false;

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
                                if (c->value_u8 != SD_BUS_MESSAGE_SIGNAL)
                                        matches_name_change = false;

                                bloom_add_pair(bloom, "message-type", bus_message_type_to_string(c->value_u8));
                                using_bloom = true;
                                break;

                        case BUS_MATCH_INTERFACE:
                                if (!streq(c->value_str, "org.freedesktop.DBus"))
                                        matches_name_change = false;

                                bloom_add_pair(bloom, "interface", c->value_str);
                                using_bloom = true;
                                break;

                        case BUS_MATCH_MEMBER:
                                if (!streq(c->value_str, "NameOwnerChanged"))
                                        matches_name_change = false;

                                bloom_add_pair(bloom, "member", c->value_str);
                                using_bloom = true;
                                break;

                        case BUS_MATCH_PATH:
                                if (!streq(c->value_str, "/org/freedesktop/DBus"))
                                        matches_name_change = false;

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

                                if (c->type - BUS_MATCH_ARG < 3)
                                        name_change_arg[c->type - BUS_MATCH_ARG] = c->value_str;

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

                        item = KDBUS_PART_NEXT(item);
                }

                if (sender) {
                        item->size = offsetof(struct kdbus_item, str) + sender_length + 1;
                        item->type = KDBUS_MATCH_SRC_NAME;
                        memcpy(item->str, sender, sender_length + 1);
                }

                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                if (r < 0)
                        return -errno;

                if (matches_name_change) {

                        /* If this match could theoretically match
                         * NameOwnerChanged messages, we need to
                         * install a second non-bloom filter explitly
                         * for it */

                        r = add_name_change_match(bus, cookie, name_change_arg[0], name_change_arg[1], name_change_arg[2]);
                        if (r < 0)
                                return r;
                }

                return 0;
        } else
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

                return 0;

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
}

_public_ int sd_bus_get_owner_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *m = NULL;
        const char *mid;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(machine, -EINVAL);
        assert_return(BUS_IS_OPEN(bus->state), -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (streq_ptr(name, bus->unique_name))
                return sd_id128_get_machine(machine);

        r = sd_bus_message_new_method_call(
                        bus,
                        name,
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId", &m);
        if (r < 0)
                return r;

        r = sd_bus_message_set_no_auto_start(m, true);
        if (r < 0)
                return r;

        r = sd_bus_call(bus, m, 0, NULL, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "s", &mid);
        if (r < 0)
                return r;

        return sd_id128_from_string(mid, machine);
}
