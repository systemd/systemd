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

#include <dbus/dbus.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "util.h"
#include "strv.h"
#include "dbus-common.h"
#include "polkit.h"
#include "def.h"
#include "virt.h"
#include "env-util.h"
#include "fileio-label.h"
#include "label.h"

#define INTERFACE \
        " <interface name=\"org.freedesktop.hostname1\">\n"             \
        "  <property name=\"Hostname\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"StaticHostname\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"PrettyHostname\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"IconName\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"Chassis\" type=\"s\" access=\"read\"/>\n"   \
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
        "  <method name=\"SetChassis\">\n"                              \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        INTERFACE                                                       \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        BUS_PEER_INTERFACE                                              \
        "</node>\n"

#define INTERFACES_LIST                         \
        BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.hostname1\0"

const char hostname_interface[] _introspect_("hostname1") = INTERFACE;

enum {
        PROP_HOSTNAME,
        PROP_STATIC_HOSTNAME,
        PROP_PRETTY_HOSTNAME,
        PROP_ICON_NAME,
        PROP_CHASSIS,
        _PROP_MAX
};

static char *data[_PROP_MAX] = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};

static usec_t remain_until = 0;

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
                           "CHASSIS", &data[PROP_CHASSIS],
                           NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        return 0;
}

static bool check_nss(void) {
        void *dl;

        dl = dlopen("libnss_myhostname.so.2", RTLD_LAZY);
        if (dl) {
                dlclose(dl);
                return true;
        }

        return false;
}

static bool valid_chassis(const char *chassis) {

        assert(chassis);

        return nulstr_contains(
                        "vm\0"
                        "container\0"
                        "desktop\0"
                        "laptop\0"
                        "server\0"
                        "tablet\0"
                        "handset\0",
                        chassis);
}

static const char* fallback_chassis(void) {
        int r;
        char *type;
        unsigned t;
        Virtualization v;

        v = detect_virtualization(NULL);

        if (v == VIRTUALIZATION_VM)
                return "vm";
        if (v == VIRTUALIZATION_CONTAINER)
                return "container";

        r = read_one_line_file("/sys/firmware/acpi/pm_profile", &type);
        if (r < 0)
                goto try_dmi;

        r = safe_atou(type, &t);
        free(type);
        if (r < 0)
                goto try_dmi;

        /* We only list the really obvious cases here as the ACPI data
         * is not really super reliable.
         *
         * See the ACPI 5.0 Spec Section 5.2.9.1 for details:
         *
         * http://www.acpi.info/DOWNLOADS/ACPIspec50.pdf
         */

        switch(t) {

        case 1:
        case 3:
        case 6:
                return "desktop";

        case 2:
                return "laptop";

        case 4:
        case 5:
        case 7:
                return "server";

        case 8:
                return "tablet";
        }

try_dmi:
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
                return "desktop";

        case 0x8:
        case 0x9:
        case 0xA:
        case 0xE:
                return "laptop";

        case 0xB:
                return "handset";

        case 0x11:
        case 0x1C:
                return "server";
        }

        return NULL;
}

static char* fallback_icon_name(void) {
        const char *chassis;

        if (!isempty(data[PROP_CHASSIS]))
                return strappend("computer-", data[PROP_CHASSIS]);

        chassis = fallback_chassis();
        if (chassis)
                return strappend("computer-", chassis);

        return strdup("computer");
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
        return write_string_file_atomic_label("/etc/hostname", data[PROP_STATIC_HOSTNAME]);
}

static int write_data_other(void) {

        static const char * const name[_PROP_MAX] = {
                [PROP_PRETTY_HOSTNAME] = "PRETTY_HOSTNAME",
                [PROP_ICON_NAME] = "ICON_NAME",
                [PROP_CHASSIS] = "CHASSIS"
        };

        char **l = NULL;
        int r, p;

        r = load_env_file("/etc/machine-info", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 2; p < _PROP_MAX; p++) {
                char *t, **u;

                assert(name[p]);

                if (isempty(data[p]))  {
                        strv_env_unset(l, name[p]);
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

        r = write_env_file_label("/etc/machine-info", l);
        strv_free(l);

        return r;
}

static int bus_hostname_append_icon_name(DBusMessageIter *i, const char *property, void *userdata) {
        const char *name;
        _cleanup_free_ char *n = NULL;

        assert(i);
        assert(property);

        if (isempty(data[PROP_ICON_NAME]))
                name = n = fallback_icon_name();
        else
                name = data[PROP_ICON_NAME];

        return bus_property_append_string(i, property, (void*) name);
}

static int bus_hostname_append_chassis(DBusMessageIter *i, const char *property, void *userdata) {
        const char *name;

        assert(i);
        assert(property);

        if (isempty(data[PROP_CHASSIS]))
                name = fallback_chassis();
        else
                name = data[PROP_CHASSIS];

        return bus_property_append_string(i, property, (void*) name);
}

static const BusProperty bus_hostname_properties[] = {
        { "Hostname",       bus_property_append_string,    "s", sizeof(data[0])*PROP_HOSTNAME,        true },
        { "StaticHostname", bus_property_append_string,    "s", sizeof(data[0])*PROP_STATIC_HOSTNAME, true },
        { "PrettyHostname", bus_property_append_string,    "s", sizeof(data[0])*PROP_PRETTY_HOSTNAME, true },
        { "IconName",       bus_hostname_append_icon_name, "s", sizeof(data[0])*PROP_ICON_NAME,       true },
        { "Chassis",        bus_hostname_append_chassis,   "s", sizeof(data[0])*PROP_CHASSIS,         true },
        { NULL, }
};

static const BusBoundProperties bps[] = {
        { "org.freedesktop.hostname1", bus_hostname_properties, data },
        { NULL, }
};

static DBusHandlerResult hostname_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {


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

                        r = verify_polkit(connection, message, "org.freedesktop.hostname1.set-hostname", interactive, NULL, &error);
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

                        log_info("Changed host name to '%s'", strna(data[PROP_HOSTNAME]));

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

                        r = verify_polkit(connection, message, "org.freedesktop.hostname1.set-static-hostname", interactive, NULL, &error);
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

                        log_info("Changed static host name to '%s'", strna(data[PROP_STATIC_HOSTNAME]));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/hostname1",
                                        "org.freedesktop.hostname1",
                                        "StaticHostname\0");
                        if (!changed)
                                goto oom;
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetPrettyHostname") ||
                   dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetIconName") ||
                   dbus_message_is_method_call(message, "org.freedesktop.hostname1", "SetChassis")) {

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

                k = streq(dbus_message_get_member(message), "SetPrettyHostname") ? PROP_PRETTY_HOSTNAME :
                        streq(dbus_message_get_member(message), "SetChassis") ? PROP_CHASSIS : PROP_ICON_NAME;

                if (!streq_ptr(name, data[k])) {

                        /* Since the pretty hostname should always be
                         * changed at the same time as the static one,
                         * use the same policy action for both... */

                        r = verify_polkit(connection, message, k == PROP_PRETTY_HOSTNAME ?
                                          "org.freedesktop.hostname1.set-static-hostname" :
                                          "org.freedesktop.hostname1.set-machine-info", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (isempty(name)) {
                                free(data[k]);
                                data[k] = NULL;
                        } else {
                                char *h;

                                /* The icon name might ultimately be
                                 * used as file name, so better be
                                 * safe than sorry */
                                if (k == PROP_ICON_NAME && !filename_is_safe(name))
                                        return bus_send_error_reply(connection, message, NULL, -EINVAL);
                                if (k == PROP_PRETTY_HOSTNAME &&
                                    (string_has_cc(name) || chars_intersect(name, "\t")))
                                        return bus_send_error_reply(connection, message, NULL, -EINVAL);
                                if (k == PROP_CHASSIS && !valid_chassis(name))
                                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

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

                        log_info("Changed %s to '%s'",
                                 k == PROP_PRETTY_HOSTNAME ? "pretty host name" :
                                 k == PROP_CHASSIS ? "chassis" : "icon name", strna(data[k]));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/hostname1",
                                        "org.freedesktop.hostname1",
                                        k == PROP_PRETTY_HOSTNAME ? "PrettyHostname\0" :
                                        k == PROP_CHASSIS ? "Chassis\0" : "IconName\0");
                        if (!changed)
                                goto oom;
                }

        } else
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, bps);

        reply = dbus_message_new_method_return(message);
        if (!reply)
                goto oom;

        if (!bus_maybe_send_reply(connection, message, reply))
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

static int connect_bus(DBusConnection **_bus) {
        static const DBusObjectPathVTable hostname_vtable = {
                .message_function = hostname_message_handler
        };
        DBusError error;
        DBusConnection *bus = NULL;
        int r;

        assert(_bus);

        dbus_error_init(&error);

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!bus) {
                log_error("Failed to get system D-Bus connection: %s", bus_error_message(&error));
                r = -ECONNREFUSED;
                goto fail;
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (!dbus_connection_register_object_path(bus, "/org/freedesktop/hostname1", &hostname_vtable, NULL) ||
            !dbus_connection_add_filter(bus, bus_exit_idle_filter, &remain_until, NULL)) {
                r = log_oom();
                goto fail;
        }

        r = dbus_bus_request_name(bus, "org.freedesktop.hostname1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EEXIST;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
                log_error("Failed to acquire name.");
                r = -EEXIST;
                goto fail;
        }

        if (_bus)
                *_bus = bus;

        return 0;

fail:
        dbus_connection_close(bus);
        dbus_connection_unref(bus);

        dbus_error_free(&error);

        return r;
}

int main(int argc, char *argv[]) {
        int r;
        DBusConnection *bus = NULL;
        bool exiting = false;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);
        label_init("/etc");

        if (argc == 2 && streq(argv[1], "--introspect")) {
                fputs(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
                      "<node>\n", stdout);
                fputs(hostname_interface, stdout);
                fputs("</node>\n", stdout);
                return 0;
        }

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        if (!check_nss())
                log_warning("Warning: nss-myhostname is not installed. Changing the local hostname might make it unresolveable. Please install nss-myhostname!");

        r = read_data();
        if (r < 0) {
                log_error("Failed to read hostname data: %s", strerror(-r));
                goto finish;
        }

        r = connect_bus(&bus);
        if (r < 0)
                goto finish;

        remain_until = now(CLOCK_MONOTONIC) + DEFAULT_EXIT_USEC;
        for (;;) {

                if (!dbus_connection_read_write_dispatch(bus, exiting ? -1 : (int) (DEFAULT_EXIT_USEC/USEC_PER_MSEC)))
                        break;

                if (!exiting && remain_until < now(CLOCK_MONOTONIC)) {
                        exiting = true;
                        bus_async_unregister_and_exit(bus, "org.freedesktop.hostname1");
                }
        }

        r = 0;

finish:
        free_data();

        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
