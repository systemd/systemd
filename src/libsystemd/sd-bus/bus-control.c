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

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <errno.h>
#include <stddef.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-bloom.h"
#include "bus-control.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "capability-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

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

static int bus_request_name_dbus1(sd_bus *bus, const char *name, uint64_t flags) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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

        return bus_request_name_dbus1(bus, name, flags);
}

static int bus_release_name_dbus1(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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

        return bus_release_name_dbus1(bus, name);
}

static int bus_list_names_dbus1(sd_bus *bus, char ***acquired, char ***activatable) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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

        return bus_list_names_dbus1(bus, acquired, activatable);
}

static int bus_get_name_creds_dbus1(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **creds) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply_unique = NULL, *reply = NULL;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
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
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                bool need_pid, need_uid, need_selinux, need_separate_calls;
                c = bus_creds_new();
                if (!c)
                        return -ENOMEM;

                if ((mask & SD_BUS_CREDS_UNIQUE_NAME) && unique) {
                        c->unique_name = strdup(unique);
                        if (!c->unique_name)
                                return -ENOMEM;

                        c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
                }

                need_pid = (mask & SD_BUS_CREDS_PID) ||
                        ((mask & SD_BUS_CREDS_AUGMENT) &&
                         (mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                                  SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                                  SD_BUS_CREDS_SUPPLEMENTARY_GIDS|
                                  SD_BUS_CREDS_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                                  SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                                  SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                                  SD_BUS_CREDS_SELINUX_CONTEXT|
                                  SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID)));
                need_uid = mask & SD_BUS_CREDS_EUID;
                need_selinux = mask & SD_BUS_CREDS_SELINUX_CONTEXT;

                if (need_pid + need_uid + need_selinux > 1) {

                        /* If we need more than one of the credentials, then use GetConnectionCredentials() */

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/org/freedesktop/DBus",
                                        "org.freedesktop.DBus",
                                        "GetConnectionCredentials",
                                        &error,
                                        &reply,
                                        "s",
                                        unique ?: name);

                        if (r < 0) {

                                if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                                        return r;

                                /* If we got an unknown method error, fall back to the invidual calls... */
                                need_separate_calls = true;
                                sd_bus_error_free(&error);

                        } else {
                                need_separate_calls = false;

                                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                                if (r < 0)
                                        return r;

                                for (;;) {
                                        const char *m;

                                        r = sd_bus_message_enter_container(reply, 'e', "sv");
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                break;

                                        r = sd_bus_message_read(reply, "s", &m);
                                        if (r < 0)
                                                return r;

                                        if (need_uid && streq(m, "UnixUserID")) {
                                                uint32_t u;

                                                r = sd_bus_message_read(reply, "v", "u", &u);
                                                if (r < 0)
                                                        return r;

                                                c->euid = u;
                                                c->mask |= SD_BUS_CREDS_EUID;

                                        } else if (need_pid && streq(m, "ProcessID")) {
                                                uint32_t p;

                                                r = sd_bus_message_read(reply, "v", "u", &p);
                                                if (r < 0)
                                                        return r;

                                                pid = p;
                                                if (mask & SD_BUS_CREDS_PID) {
                                                        c->pid = p;
                                                        c->mask |= SD_BUS_CREDS_PID;
                                                }

                                        } else if (need_selinux && streq(m, "LinuxSecurityLabel")) {
                                                const void *p = NULL;
                                                size_t sz = 0;

                                                r = sd_bus_message_enter_container(reply, 'v', "ay");
                                                if (r < 0)
                                                        return r;

                                                r = sd_bus_message_read_array(reply, 'y', &p, &sz);
                                                if (r < 0)
                                                        return r;

                                                free(c->label);
                                                c->label = strndup(p, sz);
                                                if (!c->label)
                                                        return -ENOMEM;

                                                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;

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

                                r = sd_bus_message_exit_container(reply);
                                if (r < 0)
                                        return r;

                                if (need_pid && pid == 0)
                                        return -EPROTO;
                        }

                } else /* When we only need a single field, then let's use separate calls */
                        need_separate_calls = true;

                if (need_separate_calls) {
                        if (need_pid) {
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
                                                unique ?: name);
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

                        if (need_uid) {
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

                        if (need_selinux) {
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

                                        /* no data is fine */
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

        /* Turn off augmenting if this isn't a local connection. If the connection is not local, then /proc is not
         * going to match. */
        if (!bus->is_local)
                mask &= ~SD_BUS_CREDS_AUGMENT;

        if (streq(name, "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (streq(name, "org.freedesktop.DBus"))
                return sd_bus_get_owner_creds(bus, mask, creds);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        return bus_get_name_creds_dbus1(bus, name, mask, creds);
}

static int bus_get_owner_creds_dbus1(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        pid_t pid = 0;
        bool do_label;
        int r;

        assert(bus);

        do_label = bus->label && (mask & SD_BUS_CREDS_SELINUX_CONTEXT);

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

        if (!bus->is_local)
                mask &= ~SD_BUS_CREDS_AUGMENT;

        return bus_get_owner_creds_dbus1(bus, mask, ret);
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
                unsigned n_components) {

        assert(bus);

        if (!bus->bus_client)
                return -EINVAL;

        return bus_add_match_internal_dbus1(bus, match);
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
                const char *match) {

        assert(bus);

        if (!bus->bus_client)
                return -EINVAL;

        return bus_remove_match_internal_dbus1(bus, match);
}

_public_ int sd_bus_get_name_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
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
