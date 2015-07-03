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
#include "capability.h"

_public_ int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(unique, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!bus->bus_client)
                return -EINVAL;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *unique = bus->unique_name;
        return 0;
}

static int bus_request_name_kernel(sd_bus *bus, const char *name, uint64_t flags) {
        struct kdbus_cmd *n;
        size_t size, l;
        int r;

        assert(bus);
        assert(name);

        l = strlen(name) + 1;
        size = offsetof(struct kdbus_cmd, items) + KDBUS_ITEM_SIZE(l);
        n = alloca0_align(size, 8);
        n->size = size;
        n->flags = request_name_flags_to_kdbus(flags);

        n->items[0].size = KDBUS_ITEM_HEADER_SIZE + l;
        n->items[0].type = KDBUS_ITEM_NAME;
        memcpy(n->items[0].str, name, l);

#ifdef HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_ACQUIRE, n);
        if (r < 0)
                return -errno;

        if (n->return_flags & KDBUS_NAME_IN_QUEUE)
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
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(!(flags & ~(SD_BUS_NAME_ALLOW_REPLACEMENT|SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_QUEUE)), -EINVAL);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        /* Don't allow requesting the special driver and local names */
        if (STR_IN_SET(name, "org.freedesktop.DBus", "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_request_name_kernel(bus, name, flags);
        else
                return bus_request_name_dbus1(bus, name, flags);
}

static int bus_release_name_kernel(sd_bus *bus, const char *name) {
        struct kdbus_cmd *n;
        size_t size, l;
        int r;

        assert(bus);
        assert(name);

        l = strlen(name) + 1;
        size = offsetof(struct kdbus_cmd, items) + KDBUS_ITEM_SIZE(l);
        n = alloca0_align(size, 8);
        n->size = size;

        n->items[0].size = KDBUS_ITEM_HEADER_SIZE + l;
        n->items[0].type = KDBUS_ITEM_NAME;
        memcpy(n->items[0].str, name, l);

#ifdef HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(n, n->size);
#endif
        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_RELEASE, n);
        if (r < 0)
                return -errno;

        return 0;
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
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        /* Don't allow releasing the special driver and local names */
        if (STR_IN_SET(name, "org.freedesktop.DBus", "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_release_name_kernel(bus, name);
        else
                return bus_release_name_dbus1(bus, name);
}

static int kernel_get_list(sd_bus *bus, uint64_t flags, char ***x) {
        struct kdbus_cmd_list cmd = {
                .size = sizeof(cmd),
                .flags = flags,
        };
        struct kdbus_info *name_list, *name;
        uint64_t previous_id = 0;
        int r;

        /* Caller will free half-constructed list on failure... */

        r = ioctl(bus->input_fd, KDBUS_CMD_LIST, &cmd);
        if (r < 0)
                return -errno;

        name_list = (struct kdbus_info *) ((uint8_t *) bus->kdbus_buffer + cmd.offset);

        KDBUS_FOREACH(name, name_list, cmd.list_size) {

                struct kdbus_item *item;
                const char *entry_name = NULL;

                if ((flags & KDBUS_LIST_UNIQUE) && name->id != previous_id) {
                        char *n;

                        if (asprintf(&n, ":1.%llu", (unsigned long long) name->id) < 0) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        r = strv_consume(x, n);
                        if (r < 0)
                                goto fail;

                        previous_id = name->id;
                }

                KDBUS_ITEM_FOREACH(item, name, items)
                        if (item->type == KDBUS_ITEM_OWNED_NAME)
                                entry_name = item->name.name;

                if (entry_name && service_name_is_valid(entry_name)) {
                        r = strv_extend(x, entry_name);
                        if (r < 0) {
                                r = -ENOMEM;
                                goto fail;
                        }
                }
        }

        r = 0;

fail:
        bus_kernel_cmd_free(bus, cmd.offset);
        return r;
}

static int bus_list_names_kernel(sd_bus *bus, char ***acquired, char ***activatable) {
        _cleanup_strv_free_ char **x = NULL, **y = NULL;
        int r;

        if (acquired) {
                r = kernel_get_list(bus, KDBUS_LIST_UNIQUE | KDBUS_LIST_NAMES, &x);
                if (r < 0)
                        return r;
        }

        if (activatable) {
                r = kernel_get_list(bus, KDBUS_LIST_ACTIVATORS, &y);
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

        if (!bus->bus_client)
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_list_names_kernel(bus, acquired, activatable);
        else
                return bus_list_names_dbus1(bus, acquired, activatable);
}

static int bus_populate_creds_from_items(
                sd_bus *bus,
                struct kdbus_info *info,
                uint64_t mask,
                sd_bus_creds *c) {

        struct kdbus_item *item;
        uint64_t m;
        int r;

        assert(bus);
        assert(info);
        assert(c);

        KDBUS_ITEM_FOREACH(item, info, items) {

                switch (item->type) {

                case KDBUS_ITEM_PIDS:

                        if (mask & SD_BUS_CREDS_PID && item->pids.pid > 0) {
                                c->pid = (pid_t) item->pids.pid;
                                c->mask |= SD_BUS_CREDS_PID;
                        }

                        if (mask & SD_BUS_CREDS_TID && item->pids.tid > 0) {
                                c->tid = (pid_t) item->pids.tid;
                                c->mask |= SD_BUS_CREDS_TID;
                        }

                        if (mask & SD_BUS_CREDS_PPID) {
                                if (item->pids.ppid > 0) {
                                        c->ppid = (pid_t) item->pids.ppid;
                                        c->mask |= SD_BUS_CREDS_PPID;
                                } else if (item->pids.pid == 1) {
                                        /* The structure doesn't
                                         * really distinguish the case
                                         * where a process has no
                                         * parent and where we don't
                                         * know it because it could
                                         * not be translated due to
                                         * namespaces. However, we
                                         * know that PID 1 has no
                                         * parent process, hence let's
                                         * patch that in, manually. */
                                        c->ppid = 0;
                                        c->mask |= SD_BUS_CREDS_PPID;
                                }
                        }

                        break;

                case KDBUS_ITEM_CREDS:

                        if (mask & SD_BUS_CREDS_UID && (uid_t) item->creds.uid != UID_INVALID) {
                                c->uid = (uid_t) item->creds.uid;
                                c->mask |= SD_BUS_CREDS_UID;
                        }

                        if (mask & SD_BUS_CREDS_EUID && (uid_t) item->creds.euid != UID_INVALID) {
                                c->euid = (uid_t) item->creds.euid;
                                c->mask |= SD_BUS_CREDS_EUID;
                        }

                        if (mask & SD_BUS_CREDS_SUID && (uid_t) item->creds.suid != UID_INVALID) {
                                c->suid = (uid_t) item->creds.suid;
                                c->mask |= SD_BUS_CREDS_SUID;
                        }

                        if (mask & SD_BUS_CREDS_FSUID && (uid_t) item->creds.fsuid != UID_INVALID) {
                                c->fsuid = (uid_t) item->creds.fsuid;
                                c->mask |= SD_BUS_CREDS_FSUID;
                        }

                        if (mask & SD_BUS_CREDS_GID && (gid_t) item->creds.gid != GID_INVALID) {
                                c->gid = (gid_t) item->creds.gid;
                                c->mask |= SD_BUS_CREDS_GID;
                        }

                        if (mask & SD_BUS_CREDS_EGID && (gid_t) item->creds.egid != GID_INVALID) {
                                c->egid = (gid_t) item->creds.egid;
                                c->mask |= SD_BUS_CREDS_EGID;
                        }

                        if (mask & SD_BUS_CREDS_SGID && (gid_t) item->creds.sgid != GID_INVALID) {
                                c->sgid = (gid_t) item->creds.sgid;
                                c->mask |= SD_BUS_CREDS_SGID;
                        }

                        if (mask & SD_BUS_CREDS_FSGID && (gid_t) item->creds.fsgid != GID_INVALID) {
                                c->fsgid = (gid_t) item->creds.fsgid;
                                c->mask |= SD_BUS_CREDS_FSGID;
                        }

                        break;

                case KDBUS_ITEM_PID_COMM:
                        if (mask & SD_BUS_CREDS_COMM) {
                                r = free_and_strdup(&c->comm, item->str);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_COMM;
                        }
                        break;

                case KDBUS_ITEM_TID_COMM:
                        if (mask & SD_BUS_CREDS_TID_COMM) {
                                r = free_and_strdup(&c->tid_comm, item->str);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_TID_COMM;
                        }
                        break;

                case KDBUS_ITEM_EXE:
                        if (mask & SD_BUS_CREDS_EXE) {
                                r = free_and_strdup(&c->exe, item->str);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_EXE;
                        }
                        break;

                case KDBUS_ITEM_CMDLINE:
                        if (mask & SD_BUS_CREDS_CMDLINE) {
                                c->cmdline_size = item->size - offsetof(struct kdbus_item, data);
                                c->cmdline = memdup(item->data, c->cmdline_size);
                                if (!c->cmdline)
                                        return -ENOMEM;

                                c->mask |= SD_BUS_CREDS_CMDLINE;
                        }
                        break;

                case KDBUS_ITEM_CGROUP:
                        m = (SD_BUS_CREDS_CGROUP | SD_BUS_CREDS_UNIT |
                             SD_BUS_CREDS_USER_UNIT | SD_BUS_CREDS_SLICE |
                             SD_BUS_CREDS_SESSION | SD_BUS_CREDS_OWNER_UID) & mask;

                        if (m) {
                                r = free_and_strdup(&c->cgroup, item->str);
                                if (r < 0)
                                        return r;

                                r = bus_get_root_path(bus);
                                if (r < 0)
                                        return r;

                                r = free_and_strdup(&c->cgroup_root, bus->cgroup_root);
                                if (r < 0)
                                        return r;

                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_CAPS:
                        m = (SD_BUS_CREDS_EFFECTIVE_CAPS | SD_BUS_CREDS_PERMITTED_CAPS |
                             SD_BUS_CREDS_INHERITABLE_CAPS | SD_BUS_CREDS_BOUNDING_CAPS) & mask;

                        if (m) {
                                if (item->caps.last_cap != cap_last_cap() ||
                                    item->size - offsetof(struct kdbus_item, caps.caps) < DIV_ROUND_UP(item->caps.last_cap, 32U) * 4 * 4)
                                        return -EBADMSG;

                                c->capability = memdup(item->caps.caps, item->size - offsetof(struct kdbus_item, caps.caps));
                                if (!c->capability)
                                        return -ENOMEM;

                                c->mask |= m;
                        }
                        break;

                case KDBUS_ITEM_SECLABEL:
                        if (mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                                r = free_and_strdup(&c->label, item->str);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
                        }
                        break;

                case KDBUS_ITEM_AUDIT:
                        if (mask & SD_BUS_CREDS_AUDIT_SESSION_ID) {
                                c->audit_session_id = (uint32_t) item->audit.sessionid;
                                c->mask |= SD_BUS_CREDS_AUDIT_SESSION_ID;
                        }

                        if (mask & SD_BUS_CREDS_AUDIT_LOGIN_UID) {
                                c->audit_login_uid = (uid_t) item->audit.loginuid;
                                c->mask |= SD_BUS_CREDS_AUDIT_LOGIN_UID;
                        }
                        break;

                case KDBUS_ITEM_OWNED_NAME:
                        if ((mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) && service_name_is_valid(item->name.name)) {
                                r = strv_extend(&c->well_known_names, item->name.name);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES;
                        }
                        break;

                case KDBUS_ITEM_CONN_DESCRIPTION:
                        if (mask & SD_BUS_CREDS_DESCRIPTION) {
                                r = free_and_strdup(&c->description, item->str);
                                if (r < 0)
                                        return r;

                                c->mask |= SD_BUS_CREDS_DESCRIPTION;
                        }
                        break;

                case KDBUS_ITEM_AUXGROUPS:
                        if (mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS) {
                                size_t i, n;
                                uid_t *g;

                                n = (item->size - offsetof(struct kdbus_item, data64)) / sizeof(uint64_t);
                                g = new(gid_t, n);
                                if (!g)
                                        return -ENOMEM;

                                for (i = 0; i < n; i++)
                                        g[i] = item->data64[i];

                                free(c->supplementary_gids);
                                c->supplementary_gids = g;
                                c->n_supplementary_gids = n;

                                c->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
                        }
                        break;
                }
        }

        return 0;
}

int bus_get_name_creds_kdbus(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                bool allow_activator,
                sd_bus_creds **creds) {

        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        struct kdbus_cmd_info *cmd;
        struct kdbus_info *conn_info;
        size_t size, l;
        uint64_t id;
        int r;

        if (streq(name, "org.freedesktop.DBus"))
                return -EOPNOTSUPP;

        r = bus_kernel_parse_unique_name(name, &id);
        if (r < 0)
                return r;
        if (r > 0) {
                size = offsetof(struct kdbus_cmd_info, items);
                cmd = alloca0_align(size, 8);
                cmd->id = id;
        } else {
                l = strlen(name) + 1;
                size = offsetof(struct kdbus_cmd_info, items) + KDBUS_ITEM_SIZE(l);
                cmd = alloca0_align(size, 8);
                cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + l;
                cmd->items[0].type = KDBUS_ITEM_NAME;
                memcpy(cmd->items[0].str, name, l);
        }

        /* If augmentation is on, and the bus didn't provide us
         * the bits we want, then ask for the PID/TID so that we
         * can read the rest from /proc. */
        if ((mask & SD_BUS_CREDS_AUGMENT) &&
            (mask & (SD_BUS_CREDS_PPID|
                     SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                     SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                     SD_BUS_CREDS_COMM|SD_BUS_CREDS_TID_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                     SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                     SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                     SD_BUS_CREDS_SELINUX_CONTEXT|
                     SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID)))
                mask |= SD_BUS_CREDS_PID;

        cmd->size = size;
        cmd->attach_flags = attach_flags_to_kdbus(mask);

        r = ioctl(bus->input_fd, KDBUS_CMD_CONN_INFO, cmd);
        if (r < 0)
                return -errno;

        conn_info = (struct kdbus_info *) ((uint8_t *) bus->kdbus_buffer + cmd->offset);

        /* Non-activated names are considered not available */
        if (!allow_activator && (conn_info->flags & KDBUS_HELLO_ACTIVATOR)) {
                if (name[0] == ':')
                        r = -ENXIO;
                else
                        r = -ESRCH;
                goto fail;
        }

        c = bus_creds_new();
        if (!c) {
                r = -ENOMEM;
                goto fail;
        }

        if (mask & SD_BUS_CREDS_UNIQUE_NAME) {
                if (asprintf(&c->unique_name, ":1.%llu", (unsigned long long) conn_info->id) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

                c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
        }

        /* If KDBUS_ITEM_OWNED_NAME is requested then we'll get 0 of
           them in case the service has no names. This does not mean
           however that the list of owned names could not be
           acquired. Hence, let's explicitly clarify that the data is
           complete. */
        c->mask |= mask & SD_BUS_CREDS_WELL_KNOWN_NAMES;

        r = bus_populate_creds_from_items(bus, conn_info, mask, c);
        if (r < 0)
                goto fail;

        r = bus_creds_add_more(c, mask, 0, 0);
        if (r < 0)
                goto fail;

        if (creds) {
                *creds = c;
                c = NULL;
        }

        r = 0;

fail:
        bus_kernel_cmd_free(bus, cmd->offset);
        return r;
}

static int bus_get_name_creds_dbus1(
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

                if ((mask & SD_BUS_CREDS_PID) ||
                    ((mask & SD_BUS_CREDS_AUGMENT) &&
                     (mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                              SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                              SD_BUS_CREDS_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                              SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                              SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                              SD_BUS_CREDS_SELINUX_CONTEXT|
                              SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID)))) {

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

                if (mask & SD_BUS_CREDS_EUID) {
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

                        c->euid = u;
                        c->mask |= SD_BUS_CREDS_EUID;

                        reply = sd_bus_message_unref(reply);
                }

                if (mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                        const void *p = NULL;
                        size_t sz = 0;

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/org/freedesktop/DBus",
                                        "org.freedesktop.DBus",
                                        "GetConnectionSELinuxSecurityContext",
                                        &error,
                                        &reply,
                                        "s",
                                        unique ? unique : name);
                        if (r < 0) {
                                if (!sd_bus_error_has_name(&error, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"))
                                        return r;
                        } else {
                                r = sd_bus_message_read_array(reply, 'y', &p, &sz);
                                if (r < 0)
                                        return r;

                                c->label = strndup(p, sz);
                                if (!c->label)
                                        return -ENOMEM;

                                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
                        }
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

_public_ int sd_bus_get_name_creds(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return((mask & ~SD_BUS_CREDS_AUGMENT) <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(mask == 0 || creds, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        if (streq(name, "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_get_name_creds_kdbus(bus, name, mask, false, creds);
        else
                return bus_get_name_creds_dbus1(bus, name, mask, creds);
}

static int bus_get_owner_creds_kdbus(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        struct kdbus_cmd_info cmd = {
                .size = sizeof(struct kdbus_cmd_info),
        };
        struct kdbus_info *creator_info;
        pid_t pid = 0;
        int r;

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        /* If augmentation is on, and the bus doesn't didn't allow us
         * to get the bits we want, then ask for the PID/TID so that we
         * can read the rest from /proc. */
        if ((mask & SD_BUS_CREDS_AUGMENT) &&
            (mask & (SD_BUS_CREDS_PPID|
                     SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                     SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                     SD_BUS_CREDS_COMM|SD_BUS_CREDS_TID_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                     SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                     SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                     SD_BUS_CREDS_SELINUX_CONTEXT|
                     SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID)))
                mask |= SD_BUS_CREDS_PID;

        cmd.attach_flags = attach_flags_to_kdbus(mask);

        r = ioctl(bus->input_fd, KDBUS_CMD_BUS_CREATOR_INFO, &cmd);
        if (r < 0)
                return -errno;

        creator_info = (struct kdbus_info *) ((uint8_t *) bus->kdbus_buffer + cmd.offset);

        r = bus_populate_creds_from_items(bus, creator_info, mask, c);
        bus_kernel_cmd_free(bus, cmd.offset);
        if (r < 0)
                return r;

        r = bus_creds_add_more(c, mask, pid, 0);
        if (r < 0)
                return r;

        *ret = c;
        c = NULL;
        return 0;
}

static int bus_get_owner_creds_dbus1(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        pid_t pid = 0;
        int r;
        bool do_label = bus->label && (mask & SD_BUS_CREDS_SELINUX_CONTEXT);

        /* Avoid allocating anything if we have no chance of returning useful data */
        if (!bus->ucred_valid && !do_label)
                return -ENODATA;

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        if (bus->ucred_valid) {
                if (bus->ucred.pid > 0) {
                        pid = c->pid = bus->ucred.pid;
                        c->mask |= SD_BUS_CREDS_PID & mask;
                }

                if (bus->ucred.uid != UID_INVALID) {
                        c->euid = bus->ucred.uid;
                        c->mask |= SD_BUS_CREDS_EUID & mask;
                }

                if (bus->ucred.gid != GID_INVALID) {
                        c->egid = bus->ucred.gid;
                        c->mask |= SD_BUS_CREDS_EGID & mask;
                }
        }

        if (do_label) {
                c->label = strdup(bus->label);
                if (!c->label)
                        return -ENOMEM;

                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        r = bus_creds_add_more(c, mask, pid, 0);
        if (r < 0)
                return r;

        *ret = c;
        c = NULL;
        return 0;
}

_public_ int sd_bus_get_owner_creds(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
        assert_return(bus, -EINVAL);
        assert_return((mask & ~SD_BUS_CREDS_AUGMENT) <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->is_kernel)
                return bus_get_owner_creds_kdbus(bus, mask, ret);
        else
                return bus_get_owner_creds_dbus1(bus, mask, ret);
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

                m = alloca0_align(sz, 8);
                m->size = sz;
                m->cookie = cookie;

                item = m->items;
                item->size =
                        offsetof(struct kdbus_item, name_change) +
                        offsetof(struct kdbus_notify_name_change, name) +
                        l;

                item->name_change.old_id.id = old_owner_id;
                item->name_change.new_id.id = new_owner_id;

                if (name)
                        memcpy(item->name_change.name, name, l);

                /* If the old name is unset or empty, then
                 * this can match against added names */
                if (isempty(old_owner)) {
                        item->type = KDBUS_ITEM_NAME_ADD;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* If the new name is unset or empty, then
                 * this can match against removed names */
                if (isempty(new_owner)) {
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

                m = alloca0_align(sz, 8);
                m->size = sz;
                m->cookie = cookie;

                item = m->items;
                item->size =
                        offsetof(struct kdbus_item, id_change) +
                        sizeof(struct kdbus_notify_id_change);
                item->id_change.id = name_id;

                /* If the old name is unset or empty, then this can
                 * match against added ids */
                if (isempty(old_owner)) {
                        item->type = KDBUS_ITEM_ID_ADD;
                        if (!isempty(new_owner))
                                item->id_change.id = new_owner_id;

                        r = ioctl(bus->input_fd, KDBUS_CMD_MATCH_ADD, m);
                        if (r < 0)
                                return -errno;
                }

                /* If thew new name is unset or empty, then this can
                 * match against removed ids */
                if (isempty(new_owner)) {
                        item->type = KDBUS_ITEM_ID_REMOVE;
                        if (!isempty(old_owner))
                                item->id_change.id = old_owner_id;

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
        uint64_t src_id = KDBUS_MATCH_ID_ANY, dst_id = KDBUS_MATCH_ID_ANY;
        bool using_bloom = false;
        unsigned i;
        bool matches_name_change = true;
        const char *name_change_arg[3] = {};
        int r;

        assert(bus);

        /* Monitor streams don't support matches, make this a NOP */
        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
                return 0;

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
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, "path-slash-prefix", c->value_str);
                        using_bloom = true;
                        break;

                case BUS_MATCH_ARG...BUS_MATCH_ARG_LAST: {
                        char buf[sizeof("arg")-1 + 2 + 1];

                        if (c->type - BUS_MATCH_ARG < 3)
                                name_change_arg[c->type - BUS_MATCH_ARG] = c->value_str;

                        xsprintf(buf, "arg%i", c->type - BUS_MATCH_ARG);
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, buf, c->value_str);
                        using_bloom = true;
                        break;
                }

                case BUS_MATCH_ARG_PATH...BUS_MATCH_ARG_PATH_LAST: {
                        /*
                         * XXX: DBus spec defines arg[0..63]path= matching to be
                         * a two-way glob. That is, if either string is a prefix
                         * of the other, it matches.
                         * This is really hard to realize in bloom-filters, as
                         * we would have to create a bloom-match for each prefix
                         * of @c->value_str. This is excessive, hence we just
                         * ignore all those matches and accept everything from
                         * the kernel. People should really avoid those matches.
                         * If they're used in real-life some day, we will have
                         * to properly support multiple-matches here.
                         */
                        break;
                }

                case BUS_MATCH_ARG_NAMESPACE...BUS_MATCH_ARG_NAMESPACE_LAST: {
                        char buf[sizeof("arg")-1 + 2 + sizeof("-dot-prefix")];

                        xsprintf(buf, "arg%i-dot-prefix", c->type - BUS_MATCH_ARG_NAMESPACE);
                        bloom_add_pair(bloom, bus->bloom_size, bus->bloom_n_hash, buf, c->value_str);
                        using_bloom = true;
                        break;
                }

                case BUS_MATCH_DESTINATION: {
                        /*
                         * Kernel only supports matching on destination IDs, but
                         * not on destination names. So just skip the
                         * destination name restriction and verify it in
                         * user-space on retrieval.
                         */
                        r = bus_kernel_parse_unique_name(c->value_str, &dst_id);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                sz += ALIGN8(offsetof(struct kdbus_item, id) + sizeof(uint64_t));

                        /* if not a broadcast, it cannot be a name-change */
                        if (r <= 0 || dst_id != KDBUS_DST_ID_BROADCAST)
                                matches_name_change = false;

                        break;
                }

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

        m = alloca0_align(sz, 8);
        m->size = sz;
        m->cookie = cookie;

        item = m->items;

        if (src_id != KDBUS_MATCH_ID_ANY) {
                item->size = offsetof(struct kdbus_item, id) + sizeof(uint64_t);
                item->type = KDBUS_ITEM_ID;
                item->id = src_id;
                item = KDBUS_ITEM_NEXT(item);
        }

        if (dst_id != KDBUS_MATCH_ID_ANY) {
                item->size = offsetof(struct kdbus_item, id) + sizeof(uint64_t);
                item->type = KDBUS_ITEM_DST_ID;
                item->id = dst_id;
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
         ? (isempty(m) ? "eavesdrop='true'" : strjoina((m), ",eavesdrop='true'")) \
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

        if (!bus->bus_client)
                return -EINVAL;

        if (bus->is_kernel)
                return bus_add_match_internal_kernel(bus, components, n_components, cookie);
        else
                return bus_add_match_internal_dbus1(bus, match);
}

int bus_remove_match_internal_kernel(
                sd_bus *bus,
                uint64_t cookie) {

        struct kdbus_cmd_match m = {
                .size = offsetof(struct kdbus_cmd_match, items),
                .cookie = cookie,
        };
        int r;

        assert(bus);

        /* Monitor streams don't support matches, make this a NOP */
        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
                return 0;

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

        if (!bus->bus_client)
                return -EINVAL;

        if (bus->is_kernel)
                return bus_remove_match_internal_kernel(bus, cookie);
        else
                return bus_remove_match_internal_dbus1(bus, match);
}

_public_ int sd_bus_get_name_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *m = NULL;
        const char *mid;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(machine, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

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
