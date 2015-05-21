/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers

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

#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "util.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "strv.h"
#include "set.h"
#include "driver.h"
#include "synthesize.h"

static int get_creds_by_name(sd_bus *bus, const char *name, uint64_t mask, sd_bus_creds **_creds, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(_creds);

        r = sd_bus_get_name_creds(bus, name, mask, &c);
        if (r == -ESRCH || r == -ENXIO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Name %s is currently not owned by anyone.", name);
        if (r < 0)
                return r;

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

int bus_proxy_process_driver(sd_bus *a, sd_bus *b, sd_bus_message *m, SharedPolicy *sp, const struct ucred *ucred, Set *owned_names) {
        int r;

        assert(a);
        assert(b);
        assert(m);

        if (!a->is_kernel)
                return 0;

        if (!streq_ptr(sd_bus_message_get_destination(m), "org.freedesktop.DBus"))
                return 0;

        /* The "Hello()" call is is handled in process_hello() */

        if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                return synthetic_reply_method_return(m, "s",
                        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" "
                          "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                        "<node>\n"
                        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                        "  <method name=\"Introspect\">\n"
                        "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        " </interface>\n"
                        " <interface name=\"org.freedesktop.DBus\">\n"
                        "  <method name=\"AddMatch\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <method name=\"RemoveMatch\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionCredentials\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"a{sv}\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionSELinuxSecurityContext\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"ay\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionUnixProcessID\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionUnixUser\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetId\">\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetNameOwner\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"Hello\">\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListActivatableNames\">\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListNames\">\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListQueuedOwners\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"NameHasOwner\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"b\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ReleaseName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ReloadConfig\">\n"
                        "  </method>\n"
                        "  <method name=\"RequestName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"StartServiceByName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"UpdateActivationEnvironment\">\n"
                        "   <arg type=\"a{ss}\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <signal name=\"NameAcquired\">\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        "  <signal name=\"NameLost\">\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        "  <signal name=\"NameOwnerChanged\">\n"
                        "   <arg type=\"s\"/>\n"
                        "   <arg type=\"s\"/>\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        " </interface>\n"
                        "</node>\n");

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "AddMatch")) {
                const char *match;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &match);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_add_match(a, NULL, match, NULL, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "RemoveMatch")) {
                const char *match;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &match);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = bus_remove_match_by_string(a, match, NULL, NULL);
                if (r == 0)
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_MATCH_RULE_NOT_FOUND, "Match rule not found"));
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionCredentials")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_PID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SELINUX_CONTEXT, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                r = sd_bus_message_new_method_return(m, &reply);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_open_container(reply, 'a', "{sv}");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                /* Due to i.e. namespace translations some data might be missing */

                if (creds->mask & SD_BUS_CREDS_PID) {
                        r = sd_bus_message_append(reply, "{sv}", "ProcessID", "u", (uint32_t) creds->pid);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);
                }

                if (creds->mask & SD_BUS_CREDS_EUID) {
                        r = sd_bus_message_append(reply, "{sv}", "UnixUserID", "u", (uint32_t) creds->euid);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);
                }

                if (creds->mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                        r = sd_bus_message_open_container(reply, 'e', "sv");
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_append(reply, "s", "LinuxSecurityLabel");
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_open_container(reply, 'v', "ay");
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_append_array(reply, 'y', creds->label, strlen(creds->label));
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_close_container(reply);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_close_container(reply);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);
                }

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_driver_send(m->bus, reply);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionSELinuxSecurityContext")) {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_SELINUX_CONTEXT, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                if (!(creds->mask & SD_BUS_CREDS_SELINUX_CONTEXT))
                        return synthetic_reply_method_errno(m, -EOPNOTSUPP, NULL);

                r = sd_bus_message_new_method_return(m, &reply);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_append_array(reply, 'y', creds->label, strlen(creds->label));
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_driver_send(m->bus, reply);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionUnixProcessID")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_PID, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                if (!(creds->mask & SD_BUS_CREDS_PID))
                        return synthetic_reply_method_errno(m, -EOPNOTSUPP, NULL);

                return synthetic_reply_method_return(m, "u", (uint32_t) creds->pid);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionUnixUser")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_EUID, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                if (!(creds->mask & SD_BUS_CREDS_EUID))
                        return synthetic_reply_method_errno(m, -EOPNOTSUPP, NULL);

                return synthetic_reply_method_return(m, "u", (uint32_t) creds->euid);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetId")) {
                sd_id128_t server_id;
                char buf[SD_ID128_STRING_MAX];

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_get_bus_id(a, &server_id);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "s", sd_id128_to_string(server_id, buf));

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetNameOwner")) {
                const char *name;
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "s", "org.freedesktop.DBus");

                r = get_creds_by_name(a, name, SD_BUS_CREDS_UNIQUE_NAME, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                if (!(creds->mask & SD_BUS_CREDS_UNIQUE_NAME))
                        return synthetic_reply_method_errno(m, -EOPNOTSUPP, NULL);

                return synthetic_reply_method_return(m, "s", creds->unique_name);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListActivatableNames")) {
                _cleanup_strv_free_ char **names = NULL;

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_list_names(a, NULL, &names);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                /* Let's sort the names list to make it stable */
                strv_sort(names);

                return synthetic_reply_method_return_strv(m, names);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListNames")) {
                _cleanup_strv_free_ char **names = NULL;

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_list_names(a, &names, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = strv_extend(&names, "org.freedesktop.DBus");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                /* Let's sort the names list to make it stable */
                strv_sort(names);

                return synthetic_reply_method_return_strv(m, names);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListQueuedOwners")) {
                struct kdbus_cmd_list cmd = {
                        .flags = KDBUS_LIST_QUEUED,
                        .size = sizeof(cmd),
                };
                struct kdbus_info *name_list, *name;
                _cleanup_strv_free_ char **owners = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                char *arg0;
                int err = 0;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &arg0);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_get_name_creds(a, arg0, 0, NULL);
                if (r == -ESRCH || r == -ENXIO) {
                        sd_bus_error_setf(&error, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Could not get owners of name '%s': no such name.", arg0);
                        return synthetic_reply_method_errno(m, r, &error);
                }
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = ioctl(a->input_fd, KDBUS_CMD_LIST, &cmd);
                if (r < 0)
                        return synthetic_reply_method_errno(m, -errno, NULL);

                name_list = (struct kdbus_info *) ((uint8_t *) a->kdbus_buffer + cmd.offset);

                KDBUS_FOREACH(name, name_list, cmd.list_size) {
                        const char *entry_name = NULL;
                        struct kdbus_item *item;
                        char *n;

                        KDBUS_ITEM_FOREACH(item, name, items)
                                if (item->type == KDBUS_ITEM_OWNED_NAME)
                                        entry_name = item->name.name;

                        if (!streq_ptr(entry_name, arg0))
                                continue;

                        if (asprintf(&n, ":1.%llu", (unsigned long long) name->id) < 0) {
                                err  = -ENOMEM;
                                break;
                        }

                        r = strv_consume(&owners, n);
                        if (r < 0) {
                                err = r;
                                break;
                        }
                }

                r = bus_kernel_cmd_free(a, cmd.offset);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (err < 0)
                        return synthetic_reply_method_errno(m, err, NULL);

                return synthetic_reply_method_return_strv(m, owners);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "NameHasOwner")) {
                const char *name;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "b", true);

                r = sd_bus_get_name_creds(a, name, 0, NULL);
                if (r < 0 && r != -ESRCH && r != -ENXIO)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "b", r >= 0);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ReleaseName")) {
                const char *name;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_release_name(a, name);
                if (r < 0) {
                        if (r == -ESRCH)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_NON_EXISTENT);
                        if (r == -EADDRINUSE)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_NOT_OWNER);

                        return synthetic_reply_method_errno(m, r, NULL);
                }

                set_remove(owned_names, (char*) name);

                return synthetic_reply_method_return(m, "u", BUS_NAME_RELEASED);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ReloadConfig")) {
                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = shared_policy_reload(sp);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "RequestName")) {
                const char *name;
                uint32_t flags, param;
                bool in_queue;

                if (!sd_bus_message_has_signature(m, "su"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "su", &name, &flags);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (sp) {
                        Policy *policy;
                        bool denied;

                        policy = shared_policy_acquire(sp);
                        denied = !policy_check_own(policy, ucred->uid, ucred->gid, name);
                        shared_policy_release(sp, policy);
                        if (denied)
                                return synthetic_reply_method_errno(m, -EPERM, NULL);
                }

                if ((flags & ~(BUS_NAME_ALLOW_REPLACEMENT|BUS_NAME_REPLACE_EXISTING|BUS_NAME_DO_NOT_QUEUE)) != 0)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                param = 0;
                if (flags & BUS_NAME_ALLOW_REPLACEMENT)
                        param |= SD_BUS_NAME_ALLOW_REPLACEMENT;
                if (flags & BUS_NAME_REPLACE_EXISTING)
                        param |= SD_BUS_NAME_REPLACE_EXISTING;
                if (!(flags & BUS_NAME_DO_NOT_QUEUE))
                        param |= SD_BUS_NAME_QUEUE;

                r = set_put_strdup(owned_names, name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_request_name(a, name, param);
                if (r < 0) {
                        if (r == -EALREADY)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_ALREADY_OWNER);

                        set_remove(owned_names, (char*) name);

                        if (r == -EEXIST)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_EXISTS);
                        return synthetic_reply_method_errno(m, r, NULL);
                }

                in_queue = (r == 0);

                if (in_queue)
                        return synthetic_reply_method_return(m, "u", BUS_NAME_IN_QUEUE);

                return synthetic_reply_method_return(m, "u", BUS_NAME_PRIMARY_OWNER);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "StartServiceByName")) {
                _cleanup_bus_message_unref_ sd_bus_message *msg = NULL;
                const char *name;
                uint32_t flags;

                if (!sd_bus_message_has_signature(m, "su"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "su", &name, &flags);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (flags != 0)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                r = sd_bus_get_name_creds(a, name, 0, NULL);
                if (r >= 0 || streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "u", BUS_START_REPLY_ALREADY_RUNNING);
                if (r != -ESRCH)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_new_method_call(
                                a,
                                &msg,
                                name,
                                "/",
                                "org.freedesktop.DBus.Peer",
                                "Ping");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_send(a, msg, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "u", BUS_START_REPLY_SUCCESS);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "UpdateActivationEnvironment")) {
                _cleanup_bus_message_unref_ sd_bus_message *msg = NULL;
                _cleanup_strv_free_ char **args = NULL;

                if (!sd_bus_message_has_signature(m, "a{ss}"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{ss}");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "ss")) > 0) {
                        _cleanup_free_ char *s = NULL;
                        const char *key;
                        const char *value;

                        r = sd_bus_message_read(m, "ss", &key, &value);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        s = strjoin(key, "=", value, NULL);
                        if (!s)
                                return synthetic_reply_method_errno(m, -ENOMEM, NULL);

                        r  = strv_extend(&args, s);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (!args)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                r = sd_bus_message_new_method_call(
                                a,
                                &msg,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "SetEnvironment");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_append_strv(msg, args);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_call(a, msg, 0, NULL, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                r = sd_bus_error_setf(&error, SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method '%s'.", m->member);

                return synthetic_reply_method_errno(m, r, &error);
        }
}
