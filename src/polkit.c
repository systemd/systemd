/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <sys/types.h>

#include <errno.h>

#include "util.h"
#include "dbus-common.h"
#include "polkit.h"

/* This mimics dbus_bus_get_unix_user() */
static pid_t get_unix_process_id(
                DBusConnection *connection,
                const char *name,
                DBusError *error) {

        DBusMessage *m = NULL, *reply = NULL;
        uint32_t pid = 0;

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "GetConnectionUnixProcessID");
        if (!m) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &name,
                            DBUS_TYPE_INVALID)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        if (!reply)
                goto finish;

        if (dbus_set_error_from_message(error, reply))
                goto finish;

        if (!dbus_message_get_args(
                            reply, error,
                            DBUS_TYPE_UINT32, &pid,
                            DBUS_TYPE_INVALID))
                goto finish;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return (pid_t) pid;
}

int verify_polkit(
                DBusConnection *c,
                DBusMessage *request,
                const char *action,
                bool interactive,
                bool *_challenge,
                DBusError *error) {

        DBusMessage *m = NULL, *reply = NULL;
        const char *unix_process = "unix-process", *pid = "pid", *starttime = "start-time", *cancel_id = "";
        const char *sender;
        uint32_t flags = interactive ? 1 : 0;
        pid_t pid_raw;
        uint32_t pid_u32;
        unsigned long long starttime_raw;
        uint64_t starttime_u64;
        DBusMessageIter iter_msg, iter_struct, iter_array, iter_dict, iter_variant;
        int r;
        dbus_bool_t authorized = FALSE, challenge = FALSE;

        assert(c);
        assert(request);

        sender = dbus_message_get_sender(request);
        if (!sender)
                return -EINVAL;

        pid_raw = get_unix_process_id(c, sender, error);
        if (pid_raw == 0)
                return -EINVAL;

        r = get_starttime_of_pid(pid_raw, &starttime_raw);
        if (r < 0)
                return r;

        m = dbus_message_new_method_call(
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (!m)
                return -ENOMEM;

        dbus_message_iter_init_append(m, &iter_msg);

        pid_u32 = (uint32_t) pid_raw;
        starttime_u64 = (uint64_t) starttime_raw;

        if (!dbus_message_iter_open_container(&iter_msg, DBUS_TYPE_STRUCT, NULL, &iter_struct) ||
            !dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &unix_process) ||
            !dbus_message_iter_open_container(&iter_struct, DBUS_TYPE_ARRAY, "{sv}", &iter_array) ||
            !dbus_message_iter_open_container(&iter_array, DBUS_TYPE_DICT_ENTRY, NULL, &iter_dict) ||
            !dbus_message_iter_append_basic(&iter_dict, DBUS_TYPE_STRING, &pid) ||
            !dbus_message_iter_open_container(&iter_dict, DBUS_TYPE_VARIANT, "u", &iter_variant) ||
            !dbus_message_iter_append_basic(&iter_variant, DBUS_TYPE_UINT32, &pid_u32) ||
            !dbus_message_iter_close_container(&iter_dict, &iter_variant) ||
            !dbus_message_iter_close_container(&iter_array, &iter_dict) ||
            !dbus_message_iter_open_container(&iter_array, DBUS_TYPE_DICT_ENTRY, NULL, &iter_dict) ||
            !dbus_message_iter_append_basic(&iter_dict, DBUS_TYPE_STRING, &starttime) ||
            !dbus_message_iter_open_container(&iter_dict, DBUS_TYPE_VARIANT, "t", &iter_variant) ||
            !dbus_message_iter_append_basic(&iter_variant, DBUS_TYPE_UINT64, &starttime_u64) ||
            !dbus_message_iter_close_container(&iter_dict, &iter_variant) ||
            !dbus_message_iter_close_container(&iter_array, &iter_dict) ||
            !dbus_message_iter_close_container(&iter_struct, &iter_array) ||
            !dbus_message_iter_close_container(&iter_msg, &iter_struct) ||
            !dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_STRING, &action) ||
            !dbus_message_iter_open_container(&iter_msg, DBUS_TYPE_ARRAY, "{ss}", &iter_array) ||
            !dbus_message_iter_close_container(&iter_msg, &iter_array) ||
            !dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_UINT32, &flags) ||
            !dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_STRING, &cancel_id)) {
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(c, m, -1, error);
        if (!reply) {
                r = -EIO;
                goto finish;
        }

        if (dbus_set_error_from_message(error, reply)) {
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter_msg) ||
            dbus_message_iter_get_arg_type(&iter_msg) != DBUS_TYPE_STRUCT) {
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter_msg, &iter_struct);

        if (dbus_message_iter_get_arg_type(&iter_struct) != DBUS_TYPE_BOOLEAN) {
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&iter_struct, &authorized);

        if (!dbus_message_iter_next(&iter_struct) ||
            dbus_message_iter_get_arg_type(&iter_struct) != DBUS_TYPE_BOOLEAN) {
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&iter_struct, &challenge);

        if (authorized)
                r = 1;
        else if (_challenge) {
                *_challenge = !!challenge;
                r = 0;
        } else
                r = -EPERM;

finish:

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return r;
}
