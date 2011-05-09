/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dbus/dbus.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "util.h"
#include "strv.h"
#include "dbus-common.h"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        " <interface name=\"org.freedesktop.hostname1\">\n"             \
        "  <property name=\"Hostname\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"StaticHostname\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"PrettyHostname\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"IconName\" type=\"s\" access=\"read\"/>\n"  \
        "  <method name=\"SetHostname\">\n"                             \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetStaticHostname\">\n"                       \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetPrettyHostname\">\n"                       \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetIconName\">\n"                             \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        " </interface>\n"                                               \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        BUS_PEER_INTERFACE                                              \
        "</node>\n"

#define INTERFACES_LIST                         \
        BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.hostname1\0"

enum {
        PROP_HOSTNAME,
        PROP_STATIC_HOSTNAME,
        PROP_PRETTY_HOSTNAME,
        PROP_ICON_NAME,
        _PROP_MAX
};

static char *data[_PROP_MAX] = {
        NULL,
        NULL,
        NULL,
        NULL
};

static void free_data(void) {
        int p;

        for (p = 0; p < _PROP_MAX; p++) {
                free(data[p]);
                data[p] = NULL;
        }
}

static int read_data(void) {
        int r;

        free_data();

        data[PROP_HOSTNAME] = gethostname_malloc();
        if (!data[PROP_HOSTNAME])
                return -ENOMEM;

        r = read_one_line_file("/etc/hostname", &data[PROP_STATIC_HOSTNAME]);
        if (r < 0 && r != -ENOENT)
                return r;

        r = parse_env_file("/etc/machine-info", NEWLINE,
                           "PRETTY_HOSTNAME", &data[PROP_PRETTY_HOSTNAME],
                           "ICON_NAME", &data[PROP_ICON_NAME],
                           NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        return 0;
}

static bool check_nss(void) {

        void *dl;

        if ((dl = dlopen("libnss_myhostname.so.2", RTLD_LAZY))) {
                dlclose(dl);
                return true;
        }

        return false;
}

static const char* fallback_icon_name(void) {

#if defined(__i386__) || defined(__x86_64__)
        int r;
        char *type;
        unsigned t;
#endif

        if (detect_virtualization(NULL) > 0)
                return "computer-vm";

#if defined(__i386__) || defined(__x86_64__)
        r = read_one_line_file("/sys/class/dmi/id/chassis_type", &type);
        if (r < 0)
                return NULL;

        r = safe_atou(type, &t);
        free(type);

        if (r < 0)
                return NULL;

        /* We only list the really obvious cases here. The DMI data is
           unreliable enough, so let's not do any additional guesswork
           on top of that.

           See the SMBIOS Specification 2.7.1 section 7.4.1 for
           details about the values listed here:

           http://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf
         */

        switch (t) {

        case 0x3:
        case 0x4:
        case 0x6:
        case 0x7:
                return "computer-desktop";

        case 0x9:
        case 0xA:
        case 0xE:
                return "computer-laptop";

        case 0x11:
        case 0x1C:
                return "computer-server";
        }

#endif
        return NULL;
}

static int write_data_hostname(void) {
        const char *hn;

        if (isempty(data[PROP_HOSTNAME]))
                hn = "localhost";
        else
                hn = data[PROP_HOSTNAME];

        if (sethostname(hn, strlen(hn)) < 0)
                return -errno;

        return 0;
}

static int write_data_static_hostname(void) {

        if (isempty(data[PROP_STATIC_HOSTNAME])) {

                if (unlink("/etc/hostname") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        return write_one_line_file("/etc/hostname", data[PROP_STATIC_HOSTNAME]);
}

static int write_data_other(void) {

        static const char * const name[_PROP_MAX] = {
                [PROP_PRETTY_HOSTNAME] = "PRETTY_HOSTNAME",
                [PROP_ICON_NAME] = "ICON_NAME"
        };

        char **l = NULL;
        int r, p;

        r = load_env_file("/etc/machine-info", &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 2; p < _PROP_MAX; p++) {
                char *t, **u;

                assert(name[p]);

                if (isempty(data[p]))  {
                        l = strv_env_unset(l, name[p]);
                        continue;
                }

                if (asprintf(&t, "%s=%s", name[p], strempty(data[p])) < 0) {
                        strv_free(l);
                        return -ENOMEM;
                }

                u = strv_env_set(l, t);
                free(t);
                strv_free(l);

                if (!u)
                        return -ENOMEM;
                l = u;
        }

        if (strv_isempty(l)) {

                if (unlink("/etc/machine-info") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file("/etc/machine-info", l);
        strv_free(l);

        return r;
}

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

static int verify_polkit(
                DBusConnection *c,
                DBusMessage *request,
                const char *action,
                bool interactive,
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
        dbus_bool_t authorized = FALSE;

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

        r = authorized ? 0 : -EPERM;

finish:

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return r;
}

static int bus_hostname_append_icon_name(DBusMessageIter *i, const char *property, void *userdata) {
        const char *name;

        assert(i);
        assert(property);

        if (isempty(data[PROP_ICON_NAME]))
                name = fallback_icon_name();
        else
                name = data[PROP_ICON_NAME];

        return bus_property_append_string(i, property, (void*) name);
}

static DBusHandlerResult hostname_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        const BusProperty properties[] = {
                { "org.freedesktop.hostname1", "Hostname",       bus_property_append_string,    "s", data[PROP_HOSTNAME]},
                { "org.freedesktop.hostname1", "StaticHostname", bus_property_append_string,    "s", data[PROP_STATIC_HOSTNAME]},
                { "org.freedesktop.hostname1", "PrettyHostname", bus_property_append_string,    "s", data[PROP_PRETTY_HOSTNAME]},
                { "org.freedesktop.hostname1", "IconName",       bus_hostname_append_icon_name, "s", data[PROP_ICON_NAME]},
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusMessage *reply = NULL, *changed = NULL;
        DBusError error;
        int r;

        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetHostname")) {
                const char *name;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(name))
                        name = data[PROP_STATIC_HOSTNAME];

                if (isempty(name))
                        name = "localhost";

                if (!hostname_is_valid(name))
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                if (!streq_ptr(name, data[PROP_HOSTNAME])) {
                        char *h;

                        r = verify_polkit(connection, message, "org.freedesktop.hostname1.set-hostname", interactive, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        h = strdup(name);
                        if (!h)
                                goto oom;

                        free(data[PROP_HOSTNAME]);
                        data[PROP_HOSTNAME] = h;

                        r = write_data_hostname();
                        if (r < 0) {
                                log_error("Failed to set host name: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        log_info("Changed host name to '%s'", strempty(data[PROP_HOSTNAME]));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/hostname1",
                                        "org.freedesktop.hostname1",
                                        "Hostname\0");
                        if (!changed)
                                goto oom;
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetStaticHostname")) {
                const char *name;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(name))
                        name = NULL;

                if (!streq_ptr(name, data[PROP_STATIC_HOSTNAME])) {

                        r = verify_polkit(connection, message, "org.freedesktop.hostname1.set-static-hostname", interactive, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (isempty(name)) {
                                free(data[PROP_STATIC_HOSTNAME]);
                                data[PROP_STATIC_HOSTNAME] = NULL;
                        } else {
                                char *h;

                                if (!hostname_is_valid(name))
                                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                                h = strdup(name);
                                if (!h)
                                        goto oom;

                                free(data[PROP_STATIC_HOSTNAME]);
                                data[PROP_STATIC_HOSTNAME] = h;
                        }

                        r = write_data_static_hostname();
                        if (r < 0) {
                                log_error("Failed to write static host name: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        log_info("Changed static host name to '%s'", strempty(data[PROP_HOSTNAME]));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/hostname1",
                                        "org.freedesktop.hostname1",
                                        "StaticHostname\0");
                        if (!changed)
                                goto oom;
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetPrettyHostname") ||
                   dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetIconName")) {

                const char *name;
                dbus_bool_t interactive;
                int k;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(name))
                        name = NULL;

                k = streq(dbus_message_get_member(message), "SetPrettyHostname") ? PROP_PRETTY_HOSTNAME : PROP_ICON_NAME;

                if (!streq_ptr(name, data[k])) {

                        /* Since the pretty hostname should always be
                         * changed at the same time as the static one,
                         * use the same policy action for both... */

                        r = verify_polkit(connection, message, k == PROP_PRETTY_HOSTNAME ?
                                          "org.freedesktop.hostname1.set-static-hostname" :
                                          "org.freedesktop.hostname1.set-machine-info", interactive, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (isempty(name)) {
                                free(data[k]);
                                data[k] = NULL;
                        } else {
                                char *h;

                                h = strdup(name);
                                if (!h)
                                        goto oom;

                                free(data[k]);
                                data[k] = h;
                        }

                        r = write_data_other();
                        if (r < 0) {
                                log_error("Failed to write machine info: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        log_info("Changed %s to '%s'", k == PROP_PRETTY_HOSTNAME ? "pretty host name" : "icon name", strempty(data[k]));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/hostname1",
                                        "org.freedesktop.hostname1",
                                        k == PROP_PRETTY_HOSTNAME ? "PrettyHostname\0" : "IconName\0");
                        if (!changed)
                                goto oom;
                }

        } else
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, properties);

        if (!(reply = dbus_message_new_method_return(message)))
                goto oom;

        if (!dbus_connection_send(connection, reply, NULL))
                goto oom;

        dbus_message_unref(reply);
        reply = NULL;

        if (changed) {

                if (!dbus_connection_send(connection, changed, NULL))
                        goto oom;

                dbus_message_unref(changed);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        if (changed)
                dbus_message_unref(changed);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

int main(int argc, char *argv[]) {
        const DBusObjectPathVTable hostname_vtable = {
                .message_function = hostname_message_handler
        };

        DBusConnection *bus = NULL;
        DBusError error;
        int r;

        dbus_error_init(&error);

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        if (!check_nss())
                log_warning("Warning: nss-myhostname is not installed. Changing the local hostname might make it unresolveable. Please install nss-myhostname!");

        umask(0022);

        r = read_data();
        if (r < 0) {
                log_error("Failed to read hostname data: %s", strerror(-r));
                goto finish;
        }

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!bus) {
                log_error("Failed to get system D-Bus connection: %s", error.message);
                r = -ECONNREFUSED;
                goto finish;
        }

        if (!dbus_connection_register_object_path(bus, "/org/freedesktop/hostname1", &hostname_vtable, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
                goto finish;
        }

        if (dbus_bus_request_name(bus, "org.freedesktop.hostname1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) < 0) {
                log_error("Failed to register name on bus: %s", error.message);
                r = -EEXIST;
                goto finish;
        }

        while (dbus_connection_read_write_dispatch(bus, -1))
                ;

        r = 0;

finish:
        free_data();

        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
