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
#include "bus-util.h"
#include "bus-type.h"

_public_ int sd_bus_emit_signal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *member,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_message_new_signal(bus, &m, path, interface, member);
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

_public_ int sd_bus_call_method_async(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_message_new_method_call(bus, &m, destination, path, interface, member);
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

        return sd_bus_call_async(bus, slot, m, callback, userdata, 0);
}

_public_ int sd_bus_call_method(
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

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_message_new_method_call(bus, &m, destination, path, interface, member);
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

        return sd_bus_call(bus, m, 0, error, reply);
}

_public_ int sd_bus_reply_method_return(
                sd_bus_message *call,
                const char *types, ...) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_return(call, &m);
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

        return sd_bus_send(call->bus, m, NULL);
}

_public_ int sd_bus_reply_method_error(
                sd_bus_message *call,
                const sd_bus_error *e) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(sd_bus_error_is_set(e), -EINVAL);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_error(call, &m, e);
        if (r < 0)
                return r;

        return sd_bus_send(call->bus, m, NULL);
}

_public_ int sd_bus_reply_method_errorf(
                sd_bus_message *call,
                const char *name,
                const char *format,
                ...) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        va_list ap;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        va_start(ap, format);
        bus_error_setfv(&error, name, format, ap);
        va_end(ap);

        return sd_bus_reply_method_error(call, &error);
}

_public_ int sd_bus_reply_method_errno(
                sd_bus_message *call,
                int error,
                const sd_bus_error *p) {

        _cleanup_bus_error_free_ sd_bus_error berror = SD_BUS_ERROR_NULL;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        if (sd_bus_error_is_set(p))
                return sd_bus_reply_method_error(call, p);

        sd_bus_error_set_errno(&berror, error);

        return sd_bus_reply_method_error(call, &berror);
}

_public_ int sd_bus_reply_method_errnof(
                sd_bus_message *call,
                int error,
                const char *format,
                ...) {

        _cleanup_bus_error_free_ sd_bus_error berror = SD_BUS_ERROR_NULL;
        va_list ap;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        va_start(ap, format);
        sd_bus_error_set_errnofv(&berror, error, format, ap);
        va_end(ap);

        return sd_bus_reply_method_error(call, &berror);
}

_public_ int sd_bus_get_property(
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

        assert_return(bus, -EINVAL);
        assert_return(isempty(interface) || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(reply, -EINVAL);
        assert_return(signature_is_single(type, false), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

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

_public_ int sd_bus_get_property_trivial(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                char type, void *ptr) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(isempty(interface) || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(ptr, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_call_method(bus, destination, path, "org.freedesktop.DBus.Properties", "Get", error, &reply, "ss", strempty(interface), member);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'v', CHAR_TO_STR(type));
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(reply, type, ptr);
        if (r < 0)
                return r;

        return 0;
}

_public_ int sd_bus_get_property_string(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                char **ret) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *s;
        char *n;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(isempty(interface) || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_call_method(bus, destination, path, "org.freedesktop.DBus.Properties", "Get", error, &reply, "ss", strempty(interface), member);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'v', "s");
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(reply, 's', &s);
        if (r < 0)
                return r;

        n = strdup(s);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

_public_ int sd_bus_get_property_strv(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *error,
                char ***ret) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(isempty(interface) || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_call_method(bus, destination, path, "org.freedesktop.DBus.Properties", "Get", error, &reply, "ss", strempty(interface), member);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'v', NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(reply, ret);
        if (r < 0)
                return r;

        return 0;
}

_public_ int sd_bus_set_property(
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

        assert_return(bus, -EINVAL);
        assert_return(isempty(interface) || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(signature_is_single(type, false), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = sd_bus_message_new_method_call(bus, &m, destination, path, "org.freedesktop.DBus.Properties", "Set");
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

        return sd_bus_call(bus, m, 0, error, NULL);
}

_public_ int sd_bus_query_sender_creds(sd_bus_message *call, uint64_t mask, sd_bus_creds **creds) {
        sd_bus_creds *c;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        c = sd_bus_message_get_creds(call);

        /* All data we need? */
        if (c && (mask & ~c->mask) == 0) {
                *creds = sd_bus_creds_ref(c);
                return 0;
        }

        /* No data passed? Or not enough data passed to retrieve the missing bits? */
        if (!c || !(c->mask & SD_BUS_CREDS_PID)) {
                /* We couldn't read anything from the call, let's try
                 * to get it from the sender or peer. */

                if (call->sender)
                        /* There's a sender, but the creds are
                         * missing. This means we are talking via
                         * dbus1, or are getting a message that was
                         * sent to us via kdbus, but was converted
                         * from a dbus1 message by the bus-proxy and
                         * thus also lacks the creds. */
                        return sd_bus_get_name_creds(call->bus, call->sender, mask, creds);
                else
                        /* There's no sender, hence we are on a dbus1
                         * direct connection. For direct connections
                         * the credentials of the AF_UNIX peer matter,
                         * which may be queried via
                         * sd_bus_get_owner_creds(). */
                        return sd_bus_get_owner_creds(call->bus, mask, creds);
        }

        return bus_creds_extend_by_pid(c, mask, creds);
}

_public_ int sd_bus_query_sender_privilege(sd_bus_message *call, int capability) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        uid_t our_uid;
        bool know_caps = false;
        int r;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->bus, -EINVAL);
        assert_return(!bus_pid_changed(call->bus), -ECHILD);

        if (!BUS_IS_OPEN(call->bus->state))
                return -ENOTCONN;

        if (capability >= 0) {

                r = sd_bus_query_sender_creds(call, SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS, &creds);
                if (r < 0)
                        return r;

                /* We cannot use augmented caps for authorization,
                 * since then data is acquired raceful from
                 * /proc. This can never actually happen, but let's
                 * better be safe than sorry, and do an extra check
                 * here. */
                assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_EFFECTIVE_CAPS) == 0, -EPERM);

                /* Note that not even on kdbus we might have the caps
                 * field, due to faked identities, or namespace
                 * translation issues. */
                r = sd_bus_creds_has_effective_cap(creds, capability);
                if (r > 0)
                        return 1;
                if (r == 0)
                        know_caps = true;
        } else {
                r = sd_bus_query_sender_creds(call, SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID, &creds);
                if (r < 0)
                        return r;
        }

        /* Now, check the UID, but only if the capability check wasn't
         * sufficient */
        our_uid = getuid();
        if (our_uid != 0 || !know_caps || capability < 0) {
                uid_t sender_uid;

                /* We cannot use augmented uid/euid for authorization,
                 * since then data is acquired raceful from
                 * /proc. This can never actually happen, but let's
                 * better be safe than sorry, and do an extra check
                 * here. */
                assert_return((sd_bus_creds_get_augmented_mask(creds) & (SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID)) == 0, -EPERM);

                /* Try to use the EUID, if we have it. */
                r = sd_bus_creds_get_euid(creds, &sender_uid);
                if (r < 0)
                        r = sd_bus_creds_get_uid(creds, &sender_uid);

                if (r >= 0) {
                        /* Sender has same UID as us, then let's grant access */
                        if (sender_uid == our_uid)
                                return 1;

                        /* Sender is root, we are not root. */
                        if (our_uid != 0 && sender_uid == 0)
                                return 1;
                }
        }

        return 0;
}
