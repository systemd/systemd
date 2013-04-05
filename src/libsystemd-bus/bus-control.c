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

#include <stddef.h>
#include <errno.h>

#include "strv.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-control.h"

int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        int r;

        if (!bus)
                return -EINVAL;
        if (!unique)
                return -EINVAL;

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

int sd_bus_release_name(sd_bus *bus, const char *name) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        if (!bus)
                return -EINVAL;
        if (!name)
                return -EINVAL;

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

int bus_add_match_internal(sd_bus *bus, const char *match) {
        assert(bus);
        assert(match);

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

int bus_remove_match_internal(sd_bus *bus, const char *match) {
        assert(bus);
        assert(match);

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
