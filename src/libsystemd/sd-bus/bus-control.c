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
#include "cgroup-util.h"

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

static int bus_request_name_kernel(sd_bus *bus, const char *name, uint64_t flags) {
        struct kdbus_cmd_name *n;
        size_t size, l;
        int r;

        assert(bus);
        assert(name);

        l = strlen(name);
        size = offsetof(struct kdbus_cmd_name, name) + l + 1;
        n = alloca0(size);
        n->size = size;
        kdbus_translate_request_name_flags(flags, (uint64_t *) &n->flags);
        memcpy(n->name, name, l+1);

#ifdef HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_ACQUIRE, n);
        if (r < 0)
                return -errno;

        if (n->flags & KDBUS_NAME_IN_QUEUE)
                return 0;

        return 1;
}

static int bus_request_name_dbus1(sd_bus *bus, const char *name, uint64_t flags) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret, param = 0;
        int r;

        assert(bus);
        assert(name);

        if (flags & SD_BUS_NAME_ALLOW_REPLACEMENT)
                param |= BUS_NAME_ALLOW_REPLACEMENT;
        if (flags & SD_BUS_NAME_REPLACE_EXISTING)
                param |= BUS_NAME_REPLACE_EXISTING;
        if (!(flags & SD_BUS_NAME_QUEUE))
                param |= BUS_NAME_DO_NOT_QUEUE;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "RequestName",
                        NULL,
                        &reply,
                        "su",
                        name,
                        param);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "u", &ret);
        if (r < 0)
                return r;

        if (ret == BUS_NAME_ALREADY_OWNER)
                return -EALREADY;
        else if (ret == BUS_NAME_EXISTS)
                return -EEXIST;
        else if (ret == BUS_NAME_IN_QUEUE)
                return 0;
        else if (ret == BUS_NAME_PRIMARY_OWNER)
                return 1;

        return -EIO;
}

_public_ int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) {
        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(bus->bus_client, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(!(flags & ~(SD_BUS_NAME_ALLOW_REPLACEMENT|SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_QUEUE)), -EINVAL);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_request_name_kernel(bus, name, flags);
        else
                return bus_request_name_dbus1(bus, name, flags);
}

static int bus_release_name_kernel(sd_bus *bus, const char *name) {
        struct kdbus_cmd_name *n;
        size_t l;
        int r;

        assert(bus);
        assert(name);

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
}

static int bus_release_name_dbus1(sd_bus *bus, const char *name) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        assert(bus);
        assert(name);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
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
        if (ret == BUS_NAME_NON_EXISTENT)
                return -ESRCH;
        if (ret == BUS_NAME_NOT_OWNER)
                return -EADDRINUSE;
        if (ret == BUS_NAME_RELEASED)
                return 0;

        return -EINVAL;
}

_public_ int sd_bus_release_name(sd_bus *bus, const char *name) {
        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(bus->bus_client, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_release_name_kernel(bus, name);
        else
                return bus_release_name_dbus1(bus, name);
}

static int kernel_get_list(sd_bus *bus, uint64_t flags, char ***x) {
        struct kdbus_cmd_name_list cmd = {};
        struct kdbus_name_list *name_list;
        struct kdbus_cmd_name *name;
        uint64_t previous_id = 0;
        int r;

        /* Caller will free half-constructed list on failure... */

        cmd.flags = flags;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_LIST, &cmd);
        if (r < 0)
                return -errno;

        name_list = (struct kdbus_name_list *) ((uint8_t *) bus->kdbus_buffer + cmd.offset);

        KDBUS_ITEM_FOREACH(name, name_list, names) {

                if ((flags & KDBUS_NAME_LIST_UNIQUE) && name->owner_id != previous_id) {
                        char *n;

                        if (asprintf(&n, ":1.%llu", (unsigned long long) name->owner_id) < 0)
                                return -ENOMEM;

                        r = strv_consume(x, n);
                        if (r < 0)
                                return r;

                        previous_id = name->owner_id;
                }

                if (name->size > sizeof(*name) && service_name_is_valid(name->name)) {
                        r = strv_extend(x, name->name);
                        if (r < 0)
                                return -ENOMEM;
                }
        }

        r = ioctl(bus->input_fd, KDBUS_CMD_FREE, &cmd.offset);
        if (r < 0)
                return -errno;

        return 0;
}

static int bus_list_names_kernel(sd_bus *bus, char ***acquired, char ***activatable) {
        _cleanup_strv_free_ char **x = NULL, **y = NULL;
        int r;

        if (acquired) {
                r = kernel_get_list(bus, KDBUS_NAME_LIST_UNIQUE | KDBUS_NAME_LIST_NAMES, &x);
                if (r < 0)
                        return r;
        }

        if (activatable) {
                r = kernel_get_list(bus, KDBUS_NAME_LIST_ACTIVATORS, &y);
                if (r < 0)
                        return r;

                *activatable = y;
                y = NULL;
        }

        if (acquired) {
                *acquired = x;
                x = NULL;
        }

        return 0;
}

static int bus_list_names_dbus1(sd_bus *bus, char ***acquired, char ***activatable) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **x = NULL, **y = NULL;
        int r;

        if (acquired) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "ListNames",
                                NULL,
                                &reply,
                                NULL);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_strv(reply, &x);
                if (r < 0)
                        return r;

                reply = sd_bus_message_unref(reply);
        }

        if (activatable) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "ListActivatableNames",
                                NULL,
                                &reply,
                                NULL);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_strv(reply, &y);
                if (r < 0)
                        return r;

                *activatable = y;
                y = NULL;
        }

        if (acquired) {
                *acquired = x;
                x = NULL;
        }

        return 0;
}

_public_ int sd_bus_list_names(sd_bus *bus, char ***acquired, char ***activatable) {
        assert_return(bus, -EINVAL);
        assert_return(acquired || activatable, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_list_names_kernel(bus, acquired, activatable);
        else
                return bus_list_names_dbus1(bus, acquired, activatable);
}

static int bus_get_owner_kdbus(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        struct kdbus_cmd_conn_info *cmd;
        struct kdbus_conn_info *conn_info;
        struct kdbus_item *item;
        size_t size;
        uint64_t m, id;
        int r;

        r = bus_kernel_parse_unique_name(name, &id);
        if (r < 0)
                return r;
        if (r > 0) {
                size = offsetof(struct kdbus_cmd_conn_info, name);
                cmd = alloca0(size);
                cmd->id = id;
        } else {
                size = offsetof(struct kdbus_cmd_conn_info, name) + strlen(name) + 1;
                cmd = alloca0(size);
                strcpy(cmd->name, name);
        }

        cmd->size = size;
        kdbus_translate_attach_flags(mask, (uint64_t*) &cmd->flags);

        r = ioctl(bus->input_fd, KDBUS_CMD_CONN_INFO, cmd);
        if (r < 0)
                return -errno;

        conn_info = (struct kdbus_conn_info *) ((uint8_t *) bus->kdbus_buffer + cmd->offset);

        /* Non-activated names are considered not available */
        if (conn_info->flags & KDBUS_HELLO_ACTIVATOR)
                return name[0] == ':' ? -ENXIO : -ESRCH;

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        if (mask & SD_BUS_CREDS_UNIQUE_NAME) {
                if (asprintf(&c->unique_name, ":1.%llu", (unsigned long long) conn_info->id) < 0)
                        return -ENOMEM;

                c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
        }

        KDBUS_ITEM_FOREACH(item, conn_info, items) {

                switch (item->type) {

                case KDBUS_ITEM_CREDS:
                        m = (SD_BUS_CREDS_UID | SD_BUS_CREDS_GID | SD_BUS_CREDS_PID) & mask;

                        if (m) {
                                c->uid = (uid_t) item->creds.uid;
                                c->pid = (pid_t) item->creds.pid;
                                c->gid = (gid_t) item->creds.gid;
                                c->mask |= m;
                        }

                        if (mask & SD_BUS_CREDS_TID && item->creds.tid > 0) {
                                c->tid = (pid_t) item->creds.tid;
                                c->mask |= SD_BUS_CREDS_TID;
                        }

                        if (mask & SD_BUS_CREDS_PID_STARTTIME && item->creds.starttime > 0) {
                                c->pid_starttime = item->creds.starttime;
                                c->mask |= SD_BUS_CREDS_PID_STARTTIME;
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
                                c->cmdline_size = item->size - KDBUS_ITEM_HEADER_SIZE;
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

                                if (!bus->cgroup_root) {
                                        r = cg_get_root_path(&bus->cgroup_root);
                                        if (r < 0)
                                                goto fail;
                                }

                                c->cgroup_root = strdup(bus->cgroup_root);
                                if (!c->cgroup_root) {
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
                                c->capability_size = item->size - KDBUS_ITEM_HEADER_SIZE;
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

                case KDBUS_ITEM_NAME:
                        if ((mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) && service_name_is_valid(item->name.name)) {
                                r = strv_extend(&c->well_known_names, item->name.name);
                                if (r < 0)
                                        goto fail;

                                c->mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES;
                        }
                        break;

                case KDBUS_ITEM_CONN_NAME:
                        if ((mask & SD_BUS_CREDS_CONNECTION_NAME)) {
                                c->conn_name = strdup(item->str);
                                if (!c->conn_name) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                c->mask |= SD_BUS_CREDS_CONNECTION_NAME;
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

static int bus_get_owner_dbus1(
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
                                "/org/freedesktop/DBus",
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
                                        "/org/freedesktop/DBus",
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
                                        "/org/freedesktop/DBus",
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
                        const void *p = NULL;
                        size_t sz = 0;

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/org/freedesktop/DBus",
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

_public_ int sd_bus_get_owner(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(mask <= _SD_BUS_CREDS_ALL, -ENOTSUP);
        assert_return(mask == 0 || creds, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(bus->bus_client, -ENODATA);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_get_owner_kdbus(bus, name, mask, creds);
        else
                return bus_get_owner_dbus1(bus, name, mask, creds);
}

static int add_name_change_match(sd_bus *bus,
                                 uint64_t cookie,
                                 const char *name,
                                 const char *old_owner,
                                 const char *new_owner) {

        uint64_t name_id = KDBUS_MATCH_ID_ANY, old_owner_id = 0, new_owner_id = 0;
        int is_name_id = -1, r;
        struct kdbus_item *item;

        assert(bus);

        /* If we encounter a match that could match against
         * NameOwnerChanged messages, then we need to create
         * KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE} and
         * KDBUS_ITEM_ID_{ADD,REMOVE} matches for it, possibly
         * multiple if the match is underspecified.
         *
         * The NameOwnerChanged signals take three parameters with
         * unique or well-known names, but only some forms actually
         * exist:
         *
         * WELLKNOWN, "", UNIQUE       → KDBUS_ITEM_NAME_ADD
         * WELLKNOWN, UNIQUE, ""       → KDBUS_ITEM_NAME_REMOVE
         * WELLKNOWN, UNIQUE, UNIQUE   → KDBUS_ITEM_NAME_CHANGE
         * UNIQUE, "", UNIQUE          → KDBUS_ITEM_ID_ADD
         * UNIQUE, UNIQUE, ""          → KDBUS_ITEM_ID_REMOVE
         *
         * For the latter two the two unique names must be identical.
         *
         * */

        if (name) {
                is_name_id = bus_kernel_parse_unique_name(name, &name_id);
                if (is_name_id < 0)
                        return 0;
        }

        if (!isempty(old_owner)) {
                r = bus_kernel_parse_unique_name(old_owner, &old_owner_id);
                if (r < 0)
                        return 0;
                if (r == 0)
                        return 0;
                if (is_name_id > 0 && old_owner_id != name_id)
                        return 0;
        } else
                old_owner_id = KDBUS_MATCH_ID_ANY;

        if (!isempty(new_owner)) {
                r = bus_kernel_parse_unique_name(new_owner, &new_owner_id);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;
                if (is_name_id > 0 && new_owner_id != name_id)
                        return 0;
        } else
                new_owner_id = KDBUS_MATCH_ID_ANY;

        if (is_name_id <= 0) {
                struct kdbus_cmd_match *m;
                size_t sz, l;

                /* If the name argument is missing or is a well-known
                 * name, then add KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE}
                 * matches for it */

                l = name ? strlen(name) + 1 : 0;

                sz = ALIGN8(offsetof(struct kdbus_cmd_match, items) +
                            offsetof(struct kdbus_item, name_change) +
                            offsetof(struct kdbus_notify_name_change, name) +
                            l);

                m = alloca0(sz);
                m->size = sz;
                m->cookie = cookie;

                item = m->items;
                item->size =
                        offsetof(struct kdbus_item, name_change) +
                        offsetof(struct kdbus_notify_name_change, name) +
                        l;

                item->name_change.old.id = old_owner_id;
                item->name_change.new.id = new_owner_id;

                if (name)
                        memcpy(item->name_change.name, name, l);

                /* If the old name is unset or empty, then
                 * this can match against added names */
                if (!old_owner || old_owner[0] == 0) {
                        item->type = KDBUS_ITEM_NAME_ADD;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* If the new name is unset or empty, then
                 * this can match against removed names */
                if (!new_owner || new_owner[0] == 0) {
                        item->type = KDBUS_ITEM_NAME_REMOVE;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* The CHANGE match we need in either case, because
                 * what is reported as a name change by the kernel
                 * might just be an owner change between starter and
                 * normal clients. For userspace such a change should
                 * be considered a removal/addition, hence let's
                 * subscribe to this unconditionally. */
                item->type = KDBUS_ITEM_NAME_CHANGE;
                r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                if (r < 0)
                        return -errno;
        }

        if (is_name_id != 0) {
                struct kdbus_cmd_match *m;
                uint64_t sz;

                /* If the name argument is missing or is a unique
                 * name, then add KDBUS_ITEM_ID_{ADD,REMOVE} matches
                 * for it */

                sz = ALIGN8(offsetof(struct kdbus_cmd_match, items) +
                            offsetof(struct kdbus_item, id_change) +
                            sizeof(struct kdbus_notify_id_change));

                m = alloca0(sz);
                m->size = sz;
                m->cookie = cookie;

                item = m->items;
                item->size =
                        offsetof(struct kdbus_item, id_change) +
                        sizeof(struct kdbus_notify_id_change);
                item->id_change.id = name_id;

                /* If the old name is unset or empty, then this can
                 * match against added ids */
                if (!old_owner || old_owner[0] == 0) {
                        item->type = KDBUS_ITEM_ID_ADD;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* If thew new name is unset or empty, then this can
                 * match against removed ids */
                if (!new_owner || new_owner[0] == 0) {
                        item->type = KDBUS_ITEM_ID_REMOVE;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }
        }

        return 0;
}

int bus_add_match_internal_kernel(
                sd_bus *bus,
                struct bus_match_component *components,
                unsigned n_components,
                uint64_t cookie) {

        struct kdbus_cmd_match *m;
        struct kdbus_item *item;
        uint64_t *bloom;
        size_t sz;
        const char *sender = NULL;
        size_t sender_length = 0;
        uint64_t src_id = KDBUS_MATCH_ID_ANY;
        bool using_bloom = false;
        unsigned i;
        bool matches_name_change = true;
        const char *name_change_arg[3] = {};
        int r;

        assert(bus);

        bloom = alloca0(bus->bloom_size);

        sz = ALIGN8(offsetof(struct kdbus_cmd_match, items));

        for (i = 0; i < n_components; i++) {
                struct bus_match_component *c = &components[i];

                switch (c->type) {

                case BUS_MATCH_SENDER:
                        if (!streq(c->value_str, "org.freedesktop.DBus"))
                                matches_name_change = false;

                        r = bus_kernel_parse_unique_name(c->value_str, &src_id);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                sz += ALIGN8(offsetof(struct kdbus_item, id) + sizeof(uint64_t));
                        else  {
                                sender = c->value_str;
                                sender_length = strlen(sender);
                                sz += ALIGN8(offsetof(struct kdbus_item, str) + sender_length + 1);
                        }

                        break;

                case BUS_MATCH_MESSAGE_TYPE:
                        if (c->value_u8 != SD_BUS_MESSAGE_SIGNAL)
                                matches_name_change = false;

                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "message-type", bus_message_type_to_string(c->value_u8));
                        using_bloom = true;
                        break;

                case BUS_MATCH_INTERFACE:
                        if (!streq(c->value_str, "org.freedesktop.DBus"))
                                matches_name_change = false;

                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "interface", c->value_str);
                        using_bloom = true;
                        break;

                case BUS_MATCH_MEMBER:
                        if (!streq(c->value_str, "NameOwnerChanged"))
                                matches_name_change = false;

                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "member", c->value_str);
                        using_bloom = true;
                        break;

                case BUS_MATCH_PATH:
                        if (!streq(c->value_str, "/org/freedesktop/DBus"))
                                matches_name_change = false;

                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "path", c->value_str);
                        using_bloom = true;
                        break;

                case BUS_MATCH_PATH_NAMESPACE:
                        if (!streq(c->value_str, "/")) {
                                bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "path-slash-prefix", c->value_str);
                                using_bloom = true;
                        }
                        break;

                case BUS_MATCH_ARG...BUS_MATCH_ARG_LAST: {
                        char buf[sizeof("arg")-1 + 2 + 1];

                        if (c->type - BUS_MATCH_ARG < 3)
                                name_change_arg[c->type - BUS_MATCH_ARG] = c->value_str;

                        snprintf(buf, sizeof(buf), "arg%u", c->type - BUS_MATCH_ARG);
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, buf, c->value_str);
                        using_bloom = true;
                        break;
                }

                case BUS_MATCH_ARG_PATH...BUS_MATCH_ARG_PATH_LAST: {
                        char buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];

                        snprintf(buf, sizeof(buf), "arg%u-slash-prefix", c->type - BUS_MATCH_ARG_PATH);
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, buf, c->value_str);
                        using_bloom = true;
                        break;
                }

                case BUS_MATCH_ARG_NAMESPACE...BUS_MATCH_ARG_NAMESPACE_LAST: {
                        char buf[sizeof("arg")-1 + 2 + sizeof("-dot-prefix")];

                        snprintf(buf, sizeof(buf), "arg%u-dot-prefix", c->type - BUS_MATCH_ARG_NAMESPACE);
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, buf, c->value_str);
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
                sz += ALIGN8(offsetof(struct kdbus_item, data64) + bus->bloom_size);

        m = alloca0(sz);
        m->size = sz;
        m->cookie = cookie;

        item = m->items;

        if (src_id != KDBUS_MATCH_ID_ANY) {
                item->size = offsetof(struct kdbus_item, id) + sizeof(uint64_t);
                item->type = KDBUS_ITEM_ID;
                item->id = src_id;
                item = KDBUS_ITEM_NEXT(item);
        }

        if (using_bloom) {
                item->size = offsetof(struct kdbus_item, data64) + bus->bloom_size;
                item->type = KDBUS_ITEM_BLOOM_MASK;
                memcpy(item->data64, bloom, bus->bloom_size);
                item = KDBUS_ITEM_NEXT(item);
        }

        if (sender) {
                item->size = offsetof(struct kdbus_item, str) + sender_length + 1;
                item->type = KDBUS_ITEM_NAME;
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
}

#define internal_match(bus, m)                                          \
        ((bus)->hello_flags & KDBUS_HELLO_MONITOR                       \
         ? (isempty(m) ? "eavesdrop='true'" : strappenda((m), ",eavesdrop='true'")) \
         : (m))

static int bus_add_match_internal_dbus1(
                sd_bus *bus,
                const char *match) {

        const char *e;

        assert(bus);
        assert(match);

        e = internal_match(bus, match);

        return sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "AddMatch",
                        NULL,
                        NULL,
                        "s",
                        e);
}

int bus_add_match_internal(
                sd_bus *bus,
                const char *match,
                struct bus_match_component *components,
                unsigned n_components,
                uint64_t cookie) {

        assert(bus);

        if (bus->is_kernel)
                return bus_add_match_internal_kernel(bus, components, n_components, cookie);
        else
                return bus_add_match_internal_dbus1(bus, match);
}

int bus_remove_match_internal_kernel(
                sd_bus *bus,
                uint64_t cookie) {

        struct kdbus_cmd_match m;
        int r;

        assert(bus);

        zero(m);
        m.size = offsetof(struct kdbus_cmd_match, items);
        m.cookie = cookie;

        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_REMOVE, &m);
        if (r < 0)
                return -errno;

        return 0;
}

static int bus_remove_match_internal_dbus1(
                sd_bus *bus,
                const char *match) {

        const char *e;

        assert(bus);
        assert(match);

        e = internal_match(bus, match);

        return sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "RemoveMatch",
                        NULL,
                        NULL,
                        "s",
                        e);
}

int bus_remove_match_internal(
                sd_bus *bus,
                const char *match,
                uint64_t cookie) {

        assert(bus);

        if (bus->is_kernel)
                return bus_remove_match_internal_kernel(bus, cookie);
        else
                return bus_remove_match_internal_dbus1(bus, match);
}

_public_ int sd_bus_get_owner_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *m = NULL;
        const char *mid;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(machine, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (streq_ptr(name, bus->unique_name))
                return sd_id128_get_machine(machine);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        name,
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId");
        if (r < 0)
                return r;

        r = sd_bus_message_set_auto_start(m, false);
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
