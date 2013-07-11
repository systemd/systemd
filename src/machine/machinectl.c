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

#include <dbus/dbus.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <locale.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "dbus-common.h"
#include "build.h"
#include "strv.h"
#include "unit-name.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "spawn-polkit-agent.h"

static char **arg_property = NULL;
static bool arg_all = false;
static bool arg_full = false;
static bool arg_no_pager = false;
static const char *arg_kill_who = NULL;
static int arg_signal = SIGTERM;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static bool arg_ask_password = true;
static char *arg_host = NULL;
static char *arg_user = NULL;

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

static int list_machines(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;
        int r;

        pager_open_if_enabled();

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "ListMachines",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%-32s %-9s %-16s\n", "MACHINE", "CONTAINER", "SERVICE");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name, *class, *service, *object;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &class, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &service, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                printf("%-32s %-9s %-16s\n", name, class, service);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u machines listed.\n", k);

        return 0;
}

static int show_scope_cgroup(DBusConnection *bus, const char *unit, pid_t leader) {
        const char *interface = "org.freedesktop.systemd1.Scope";
        const char *property = "ControlGroup";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *path = NULL;
        DBusMessageIter iter, sub;
        const char *cgroup;
        DBusError error;
        int r, output_flags;
        unsigned c;

        assert(bus);
        assert(unit);

        if (arg_transport == TRANSPORT_SSH)
                return 0;

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        &error,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &property,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to query ControlGroup: %s", bus_error(&error, r));
                dbus_error_free(&error);
                return r;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_recurse(&iter, &sub);
        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_get_basic(&sub, &cgroup);

        if (isempty(cgroup))
                return 0;

        if (cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, cgroup, false) != 0 && leader <= 0)
                return 0;

        output_flags =
                arg_all * OUTPUT_SHOW_ALL |
                arg_full * OUTPUT_FULL_WIDTH;

        c = columns();
        if (c > 18)
                c -= 18;
        else
                c = 0;

        show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, cgroup, "\t\t  ", c, false, &leader, leader > 0, output_flags);
        return 0;
}

typedef struct MachineStatusInfo {
        const char *name;
        sd_id128_t id;
        const char *class;
        const char *service;
        const char *scope;
        const char *root_directory;
        pid_t leader;
        usec_t timestamp;
} MachineStatusInfo;

static void print_machine_status_info(DBusConnection *bus, MachineStatusInfo *i) {
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        assert(i);

        fputs(strna(i->name), stdout);

        if (!sd_id128_equal(i->id, SD_ID128_NULL))
                printf("(" SD_ID128_FORMAT_STR ")\n", SD_ID128_FORMAT_VAL(i->id));
        else
                putchar('\n');

        s1 = format_timestamp_relative(since1, sizeof(since1), i->timestamp);
        s2 = format_timestamp(since2, sizeof(since2), i->timestamp);

        if (s1)
                printf("\t   Since: %s; %s\n", s2, s1);
        else if (s2)
                printf("\t   Since: %s\n", s2);

        if (i->leader > 0) {
                _cleanup_free_ char *t = NULL;

                printf("\t  Leader: %u", (unsigned) i->leader);

                get_process_comm(i->leader, &t);
                if (t)
                        printf(" (%s)", t);

                putchar('\n');
        }

        if (i->service) {
                printf("\t Service: %s", i->service);

                if (i->class)
                        printf("; class %s", i->class);

                putchar('\n');
        } else if (i->class)
                printf("\t   Class: %s\n", i->class);

        if (i->root_directory)
                printf("\t    Root: %s\n", i->root_directory);

        if (i->scope) {
                printf("\t    Unit: %s\n", i->scope);
                show_scope_cgroup(bus, i->scope, i->leader);
        }
}

static int status_property_machine(const char *name, DBusMessageIter *iter, MachineStatusInfo *i) {
        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Name"))
                                i->name = s;
                        else if (streq(name, "Class"))
                                i->class = s;
                        else if (streq(name, "Service"))
                                i->service = s;
                        else if (streq(name, "Scope"))
                                i->scope = s;
                        else if (streq(name, "RootDirectory"))
                                i->root_directory = s;
                }
                break;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "Leader"))
                        i->leader = (pid_t) u;

                break;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "Timestamp"))
                        i->timestamp = (usec_t) u;

                break;
        }

        case DBUS_TYPE_ARRAY: {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_BYTE && streq(name, "Id")) {
                        void *v;
                        int n;

                        dbus_message_iter_get_fixed_array(&sub, &v, &n);
                        if (n == 0)
                                i->id = SD_ID128_NULL;
                        else if (n == 16)
                                memcpy(&i->id, v, n);
                }

                break;
        }
        }

        return 0;
}

static int print_property(const char *name, DBusMessageIter *iter) {
        assert(name);
        assert(iter);

        if (arg_property && !strv_find(arg_property, name))
                return 0;

        if (generic_print_property(name, iter, arg_all) > 0)
                return 0;

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(const char *verb, DBusConnection *bus, const char *path, bool show_properties, bool *new_line) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;
        MachineStatusInfo machine_info = {};

        assert(path);
        assert(new_line);

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.machine1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                goto finish;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (*new_line)
                printf("\n");

        *new_line = true;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                if (show_properties)
                        r = print_property(name, &sub3);
                else
                        r = status_property_machine(name, &sub3, &machine_info);

                if (r < 0) {
                        log_error("Failed to parse reply.");
                        goto finish;
                }

                dbus_message_iter_next(&sub);
        }

        if (!show_properties)
                print_machine_status_info(bus, &machine_info);

        r = 0;

finish:

        return r;
}

static int show(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r, ret = 0;
        DBusError error;
        unsigned i;
        bool show_properties, new_line = false;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        show_properties = !strstr(args[0], "status");

        pager_open_if_enabled();

        if (show_properties && n <= 1) {
                /* If not argument is specified inspect the manager
                 * itself */

                ret = show_one(args[0], bus, "/org/freedesktop/machine1", show_properties, &new_line);
                goto finish;
        }

        for (i = 1; i < n; i++) {
                const char *path = NULL;

                ret = bus_method_call_with_reply(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "GetMachine",
                                &reply,
                                NULL,
                                DBUS_TYPE_STRING, &args[i],
                                DBUS_TYPE_INVALID);
                if (ret < 0)
                        goto finish;

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        ret = -EIO;
                        goto finish;
                }

                r = show_one(args[0], bus, path, show_properties, &new_line);
                if (r != 0)
                        ret = r;
        }

finish:
        dbus_error_free(&error);

        return ret;
}

static int kill_machine(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < n; i++) {
                int r;

                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "KillMachine",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &args[i],
                        DBUS_TYPE_STRING, &arg_kill_who,
                        DBUS_TYPE_INT32, &arg_signal,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int terminate_machine(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {
                int r;

                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "TerminateMachine",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &args[i],
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the virtual machine and container registration manager.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "  -p --property=NAME     Show only properties by this name\n"
               "  -a --all               Show all properties, including empty ones\n"
               "     --kill-who=WHO      Who to send signal to\n"
               "  -l --full              Do not ellipsize output\n"
               "  -s --signal=SIGNAL     Which signal to send\n"
               "     --no-ask-password   Don't prompt for password\n"
               "  -H --host=[USER@]HOST  Show information for remote host\n"
               "  -P --privileged        Acquire privileges before execution\n"
               "     --no-pager          Do not pipe output into a pager\n\n"
               "Commands:\n"
               "  list                   List running VMs and containers\n"
               "  status [NAME...]       Show VM/container status\n"
               "  show [NAME...]         Show properties of one or more VMs/containers\n"
               "  terminate [NAME...]    Terminate one or more VMs/containers\n"
               "  kill [NAME...]         Send signal to processes of a VM/container\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_KILL_WHO,
                ARG_NO_ASK_PASSWORD,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "property",        required_argument, NULL, 'p'                 },
                { "all",             no_argument,       NULL, 'a'                 },
                { "full",            no_argument,       NULL, 'l'                 },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "kill-who",        required_argument, NULL, ARG_KILL_WHO        },
                { "signal",          required_argument, NULL, 's'                 },
                { "host",            required_argument, NULL, 'H'                 },
                { "privileged",      no_argument,       NULL, 'P'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { NULL,              0,                 NULL, 0                   }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:als:H:P", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'p': {
                        char **l;

                        l = strv_append(arg_property, optarg);
                        if (!l)
                                return -ENOMEM;

                        strv_free(arg_property);
                        arg_property = l;

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
                        break;
                }

                case 'a':
                        arg_all = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case 's':
                        arg_signal = signal_from_string_try_harder(optarg);
                        if (arg_signal < 0) {
                                log_error("Failed to parse signal string %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        parse_user_at_host(optarg, &arg_user, &arg_host);
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

static int machinectl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

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
                { "list",                  LESS,   1, list_machines     },
                { "status",                MORE,   2, show              },
                { "show",                  MORE,   1, show              },
                { "terminate",             MORE,   2, terminate_machine },
                { "kill",                  MORE,   2, kill_machine      },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-sessions" */
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

int main(int argc, char*argv[]) {
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

        r = machinectl_main(bus, argc, argv, &error);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
        dbus_shutdown();

        strv_free(arg_property);

        pager_close();

        return retval;
}
