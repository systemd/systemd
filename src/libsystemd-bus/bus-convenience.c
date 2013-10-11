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

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-signature.h"

int sd_bus_emit_signal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *member,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        if (!bus)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_message_new_signal(bus, path, interface, member, &m);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = bus_message_append_ap(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return sd_bus_send(bus, m, NULL);
}

int sd_bus_call_method(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        if (!bus)

                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        r = sd_bus_message_new_method_call(bus, destination, path, interface, member, &m);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = bus_message_append_ap(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return sd_bus_send_with_reply_and_block(bus, m, 0, error, reply);
}

int sd_bus_reply_method_return(
                sd_bus *bus,
                sd_bus_message *call,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        if (!bus)
                return -EINVAL;
        if (!call)
                return -EINVAL;
        if (!call->sealed)
                return -EPERM;
        if (call->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        if (call->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_return(bus, call, &m);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = bus_message_append_ap(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return sd_bus_send(bus, m, NULL);
}

int sd_bus_reply_method_error(
                sd_bus *bus,
                sd_bus_message *call,
                const sd_bus_error *e) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        if (!bus)
                return -EINVAL;
        if (!call)
                return -EINVAL;
        if (!call->sealed)
                return -EPERM;
        if (call->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (!sd_bus_error_is_set(e))
                return -EINVAL;
        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;
        if (bus_pid_changed(bus))
                return -ECHILD;

        if (call->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_error(bus, call, e, &m);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

int sd_bus_reply_method_errorf(
                sd_bus *bus,
                sd_bus_message *call,
                const char *name,
                const char *format,
                ...) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        va_list ap;
        int r;

        error.name = strdup(name);
        if (!error.name)
                return -ENOMEM;

        error.need_free = true;

        if (format) {
                va_start(ap, format);
                r = vasprintf((char**) &error.message, format, ap);
                va_end(ap);

                if (r < 0)
                        return -ENOMEM;
        }

        return sd_bus_reply_method_error(bus, call, &error);
}

int sd_bus_get_property(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *type) {

        sd_bus_message *rep = NULL;
        int r;

        if (interface && !interface_name_is_valid(interface))
                return -EINVAL;
        if (!member_name_is_valid(member))
                return -EINVAL;
        if (!signature_is_single(type, false))
                return -EINVAL;
        if (!reply)
                return -EINVAL;

        r = sd_bus_call_method(bus, destination, path, "org.freedesktop.DBus.Properties", "Get", error, &rep, "ss", strempty(interface), member);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(rep, 'v', type);
        if (r < 0) {
                sd_bus_message_unref(rep);
                return r;
        }

        *reply = rep;
        return 0;
}

int sd_bus_set_property(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                const char *type, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        va_list ap;
        int r;

        if (interface && !interface_name_is_valid(interface))
                return -EINVAL;
        if (!member_name_is_valid(member))
                return -EINVAL;
        if (!signature_is_single(type, false))
                return -EINVAL;

        r = sd_bus_message_new_method_call(bus, destination, path, "org.freedesktop.DBus.Properties", "Set", &m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", strempty(interface), member);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'v', type);
        if (r < 0)
                return r;

        va_start(ap, type);
        r = bus_message_append_ap(m, type, ap);
        va_end(ap);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        return sd_bus_send_with_reply_and_block(bus, m, 0, error, NULL);
}
