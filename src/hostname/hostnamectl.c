/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <sys/timex.h>
#include <sys/utsname.h>

#include "dbus-common.h"
#include "util.h"
#include "spawn-polkit-agent.h"
#include "build.h"
#include "hwclock.h"
#include "strv.h"
#include "sd-id128.h"
#include "virt.h"
#include "fileio.h"

static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static bool arg_ask_password = true;
static char *arg_host = NULL;
static char *arg_user = NULL;
static bool arg_transient = false;
static bool arg_pretty = false;
static bool arg_static = false;

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        polkit_agent_open();
}

typedef struct StatusInfo {
        const char *hostname;
        const char *static_hostname;
        const char *pretty_hostname;
        const char *icon_name;
        const char *chassis;
} StatusInfo;

static void print_status_info(StatusInfo *i) {
        sd_id128_t mid, bid;
        int r;
        const char *id = NULL;
        _cleanup_free_ char *pretty_name = NULL, *cpe_name = NULL;
        struct utsname u;

        assert(i);

        printf("   Static hostname: %s\n",
               strna(i->static_hostname));

        if (!isempty(i->pretty_hostname) &&
            !streq_ptr(i->pretty_hostname, i->static_hostname))
                printf("   Pretty hostname: %s\n",
                       strna(i->pretty_hostname));

        if (!isempty(i->hostname) &&
            !streq_ptr(i->hostname, i->static_hostname))
                printf("Transient hostname: %s\n",
                       strna(i->hostname));

        printf("         Icon name: %s\n"
               "           Chassis: %s\n",
               strna(i->icon_name),
               strna(i->chassis));

        r = sd_id128_get_machine(&mid);
        if (r >= 0)
                printf("        Machine ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(mid));

        r = sd_id128_get_boot(&bid);
        if (r >= 0)
                printf("           Boot ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(bid));

        if (detect_virtualization(&id) > 0)
                printf("    Virtualization: %s\n", id);

        r = parse_env_file("/etc/os-release", NEWLINE,
                           "PRETTY_NAME", &pretty_name,
                           "CPE_NAME", &cpe_name,
                           NULL);

        if (!isempty(pretty_name))
                printf("  Operating System: %s\n", pretty_name);

        if (!isempty(cpe_name))
                printf("       CPE OS Name: %s\n", cpe_name);

        assert_se(uname(&u) >= 0);
        printf("            Kernel: %s %s\n"
               "      Architecture: %s\n", u.sysname, u.release, u.machine);

}

static int status_property(const char *name, DBusMessageIter *iter, StatusInfo *i) {
        assert(name);
        assert(iter);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);
                if (!isempty(s)) {
                        if (streq(name, "Hostname"))
                                i->hostname = s;
                        if (streq(name, "StaticHostname"))
                                i->static_hostname = s;
                        if (streq(name, "PrettyHostname"))
                                i->pretty_hostname = s;
                        if (streq(name, "IconName"))
                                i->icon_name = s;
                        if (streq(name, "Chassis"))
                                i->chassis = s;
                }
                break;
        }
        }

        return 0;
}

static int show_one_name(DBusConnection *bus, const char* attr) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "org.freedesktop.hostname1", *s;
        DBusMessageIter iter, sub;
        int r;

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &attr,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_get_basic(&sub, &s);
        printf("%s\n", s);

        return 0;
}

static int show_all_names(DBusConnection *bus) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;
        StatusInfo info = {};

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                r = status_property(name, &sub3, &info);
                if (r < 0) {
                        log_error("Failed to parse reply.");
                        return r;
                }

                dbus_message_iter_next(&sub);
        }

        print_status_info(&info);
        return 0;
}

static int show_status(DBusConnection *bus, char **args, unsigned n) {
        assert(args);

        if (arg_pretty || arg_static || arg_transient) {
                const char *attr;

                if (!!arg_static + !!arg_pretty + !!arg_transient > 1) {
                        log_error("Cannot query more than one name type at a time");
                        return -EINVAL;
                }

                attr = arg_pretty ? "PrettyHostname" :
                        arg_static ? "StaticHostname" : "Hostname";

                return show_one_name(bus, attr);
        } else
                return show_all_names(bus);
}

static int set_hostname(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = arg_ask_password;
        _cleanup_free_ char *h = NULL;
        const char *hostname = args[1];
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        if (!arg_pretty && !arg_static && !arg_transient)
                arg_pretty = arg_static = arg_transient = true;

        if (arg_pretty) {
                const char *p;

                /* If the passed hostname is already valid, then
                 * assume the user doesn't know anything about pretty
                 * hostnames, so let's unset the pretty hostname, and
                 * just set the passed hostname as static/dynamic
                 * hostname. */

                h = strdup(hostname);
                if (!h)
                        return log_oom();

                hostname_cleanup(h, true);

                if (arg_static && streq(h, hostname))
                        p = "";
                else {
                        p = hostname;
                        hostname = h;
                }

                r = bus_method_call_with_reply(
                                bus,
                                "org.freedesktop.hostname1",
                                "/org/freedesktop/hostname1",
                                "org.freedesktop.hostname1",
                                "SetPrettyHostname",
                                &reply,
                                NULL,
                                DBUS_TYPE_STRING, &p,
                                DBUS_TYPE_BOOLEAN, &interactive,
                                DBUS_TYPE_INVALID);
                if (r < 0)
                        return r;

                dbus_message_unref(reply);
                reply = NULL;
        }

        if (arg_static) {
                r = bus_method_call_with_reply(
                                bus,
                                "org.freedesktop.hostname1",
                                "/org/freedesktop/hostname1",
                                "org.freedesktop.hostname1",
                                "SetStaticHostname",
                                &reply,
                                NULL,
                                DBUS_TYPE_STRING, &hostname,
                                DBUS_TYPE_BOOLEAN, &interactive,
                                DBUS_TYPE_INVALID);

                if (r < 0)
                        return r;

                dbus_message_unref(reply);
                reply = NULL;
        }

        if (arg_transient) {
                r = bus_method_call_with_reply(
                                bus,
                                "org.freedesktop.hostname1",
                                "/org/freedesktop/hostname1",
                                "org.freedesktop.hostname1",
                                "SetHostname",
                                &reply,
                                NULL,
                                DBUS_TYPE_STRING, &hostname,
                                DBUS_TYPE_BOOLEAN, &interactive,
                                DBUS_TYPE_INVALID);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int set_icon_name(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = arg_ask_password;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "SetIconName",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &args[1],
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int set_chassis(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = arg_ask_password;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        "SetChassis",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &args[1],
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int help(void) {

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change system hostname.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --transient         Only set transient hostname\n"
               "     --static            Only set static hostname\n"
               "     --pretty            Only set pretty hostname\n"
               "  -P --privileged        Acquire privileges before execution\n"
               "     --no-ask-password   Do not prompt for password\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n\n"
               "Commands:\n"
               "  status                 Show current hostname settings\n"
               "  set-hostname NAME      Set system hostname\n"
               "  set-icon-name NAME     Set icon name for host\n"
               "  set-chassis NAME       Set chassis type for host\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_ASK_PASSWORD,
                ARG_TRANSIENT,
                ARG_STATIC,
                ARG_PRETTY
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "transient",       no_argument,       NULL, ARG_TRANSIENT   },
                { "static",          no_argument,       NULL, ARG_STATIC      },
                { "pretty",          no_argument,       NULL, ARG_PRETTY      },
                { "host",            required_argument, NULL, 'H'                 },
                { "privileged",      no_argument,       NULL, 'P'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { NULL,              0,                 NULL, 0                   }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:P", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        parse_user_at_host(optarg, &arg_user, &arg_host);
                        break;

                case ARG_TRANSIENT:
                        arg_transient = true;
                        break;

                case ARG_PRETTY:
                        arg_pretty = true;
                        break;

                case ARG_STATIC:
                        arg_static = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

static int hostnamectl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(DBusConnection *bus, char **args, unsigned n);
        } verbs[] = {
                { "status",        LESS,  1, show_status   },
                { "set-hostname",  EQUAL, 2, set_hostname  },
                { "set-icon-name", EQUAL, 2, set_icon_name },
                { "set-chassis",   EQUAL, 2, set_chassis   },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "status" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        if (!bus) {
                log_error("Failed to get D-Bus connection: %s", error->message);
                return -EIO;
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char *argv[]) {
        int r, retval = EXIT_FAILURE;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (arg_transport == TRANSPORT_NORMAL)
                bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        else if (arg_transport == TRANSPORT_POLKIT)
                bus_connect_system_polkit(&bus, &error);
        else if (arg_transport == TRANSPORT_SSH)
                bus_connect_system_ssh(NULL, arg_host, &bus, &error);
        else
                assert_not_reached("Uh, invalid transport...");

        r = hostnamectl_main(bus, argc, argv, &error);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
        dbus_shutdown();

        return retval;
}
