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

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <locale.h>

#include "sd-bus.h"

#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "bus-util.h"
#include "bus-error.h"
#include "build.h"
#include "strv.h"
#include "unit-name.h"
#include "cgroup-show.h"
#include "cgroup-util.h"

static char **arg_property = NULL;
static bool arg_all = false;
static bool arg_full = false;
static bool arg_no_pager = false;
static const char *arg_kill_who = NULL;
static int arg_signal = SIGTERM;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
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

static int list_machines(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *name, *class, *service, *object;
        unsigned k = 0;
        int r;

        pager_open_if_enabled();

        r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "ListMachines",
                                &error,
                                &reply,
                                "");
        if (r < 0) {
                log_error("Could not get machines: %s", bus_error_message(&error, -r));
                return r;
        }

        if (on_tty())
                printf("%-32s %-9s %-16s\n", "MACHINE", "CONTAINER", "SERVICE");

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssso)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_read(reply, "(ssso)", &name, &class, &service, &object)) > 0) {
                if (r < 0)
                        goto fail;

                printf("%-32s %-9s %-16s\n", name, class, service);

                k++;
        }
        if (r < 0)
                goto fail;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto fail;

        if (on_tty())
                printf("\n%u machines listed.\n", k);

        return 0;

fail:
        log_error("Failed to parse reply: %s", strerror(-r));
        return -EIO;
}

static int show_scope_cgroup(sd_bus *bus, const char *unit, pid_t leader) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        const char *cgroup;
        int r, output_flags;
        unsigned c;

        assert(bus);
        assert(unit);

        if (arg_transport == TRANSPORT_SSH)
                return 0;

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &error,
                        &reply,
                        "ss",
                        "org.freedesktop.systemd1.Scope",
                        "ControlGroup");
        if (r < 0) {
                log_error("Failed to query ControlGroup: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "v", "s", &cgroup);
        if (r < 0) {
                log_error("Failed to parse reply: %s", strerror(-r));
                return r;
        }

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

static void print_machine_status_info(sd_bus *bus, MachineStatusInfo *i) {
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

static int status_property_machine(const char *name, sd_bus_message *property, MachineStatusInfo *i) {
        char type;
        const char *contents;
        int r;

        assert(name);
        assert(property);
        assert(i);

        r = sd_bus_message_peek_type(property, &type, &contents);
        if (r < 0) {
                log_error("Could not determine type of message: %s", strerror(-r));
                return r;
        }

        switch (type) {

        case SD_BUS_TYPE_STRING: {
                const char *s;

                sd_bus_message_read_basic(property, type, &s);

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

        case SD_BUS_TYPE_UINT32: {
                uint32_t u;

                sd_bus_message_read_basic(property, type, &u);

                if (streq(name, "Leader"))
                        i->leader = (pid_t) u;

                break;
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t u;

                sd_bus_message_read_basic(property, type, &u);

                if (streq(name, "Timestamp"))
                        i->timestamp = (usec_t) u;

                break;
        }

        case SD_BUS_TYPE_ARRAY: {
                if (streq(contents, "y") && streq(name, "Id")) {
                        const void *v;
                        size_t n;

                        sd_bus_message_read_array(property, SD_BUS_TYPE_BYTE, &v, &n);
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

static int print_property(const char *name, sd_bus_message *reply) {
        assert(name);
        assert(reply);

        if (arg_property && !strv_find(arg_property, name))
                return 0;

        if (bus_generic_print_property(name, reply, arg_all) > 0)
                return 0;

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(const char *verb, sd_bus *bus, const char *path, bool show_properties, bool *new_line) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;
        MachineStatusInfo machine_info = {};

        assert(path);
        assert(new_line);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &error,
                        &reply,
                        "s", "");
        if (r < 0) {
                log_error("Could not get properties: %s", bus_error_message(&error, -r));
                return r;
        }


        if (*new_line)
                printf("\n");

        *new_line = true;

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const char *name;
                const char *contents;

                if (r < 0)
                        goto fail;

                r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_STRING, &name);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_peek_type(reply, NULL, &contents);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, contents);
                if (r < 0)
                        goto fail;

                if (show_properties)
                        r = print_property(name, reply);
                else
                        r = status_property_machine(name, reply, &machine_info);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto fail;
        }
        if (r < 0)
                goto fail;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto fail;

        if (!show_properties)
                print_machine_status_info(bus, &machine_info);

        return 0;

fail:
        log_error("Failed to parse reply: %s", strerror(-r));
        return -EIO;
}

static int show(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, ret = 0;
        unsigned i;
        bool show_properties, new_line = false;

        assert(bus);
        assert(args);

        show_properties = !strstr(args[0], "status");

        pager_open_if_enabled();

        if (show_properties && n <= 1) {

                /* If no argument is specified inspect the manager
                 * itself */

                return show_one(args[0], bus, "/org/freedesktop/machine1", show_properties, &new_line);
        }

        for (i = 1; i < n; i++) {
                const char *path = NULL;

                r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.machine1",
                                        "/org/freedesktop/machine1",
                                        "org.freedesktop.machine1.Manager",
                                        "GetMachine",
                                        &error,
                                        &reply,
                                        "s", args[i]);
                if (r < 0) {
                        log_error("Could not get path to machine: %s", bus_error_message(&error, -r));
                        return r;
                }

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0) {
                        log_error("Failed to parse reply: %s", strerror(-r));
                        return -EIO;
                }

                r = show_one(args[0], bus, path, show_properties, &new_line);
                if (r != 0)
                        ret = r;
        }

        return ret;
}

static int kill_machine(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned i;

        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < n; i++) {
                int r;

                r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.machine1",
                                        "/org/freedesktop/machine1",
                                        "org.freedesktop.machine1.Manager",
                                        "KillMachine",
                                        &error,
                                        NULL,
                                        "ssi", args[i], arg_kill_who, arg_signal);
                if (r < 0) {
                        log_error("Could not kill machine: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int terminate_machine(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {
                int r;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "TerminateMachine",
                                &error,
                                NULL,
                                "s", args[i]);
                if (r < 0) {
                        log_error("Could not terminate machine: %s", bus_error_message(&error, -r));
                        return r;
                }
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

static int machinectl_main(sd_bus *bus, int argc, char *argv[], const int r) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(sd_bus *bus, char **args, unsigned n);
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

        if (r < 0) {
                log_error("Failed to get D-Bus connection: %s", strerror(-r));
                return -EIO;
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char*argv[]) {
        int r, retval = EXIT_FAILURE;
        _cleanup_bus_unref_ sd_bus *bus = NULL;

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
                r = sd_bus_open_system(&bus);
        else if (arg_transport == TRANSPORT_SSH)
                r = bus_connect_system_ssh(arg_host, &bus);
        else
                assert_not_reached("Uh, invalid transport...");
        if (r < 0) {
                retval = EXIT_FAILURE;
                goto finish;
        }

        r = machinectl_main(bus, argc, argv, r);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        strv_free(arg_property);

        pager_close();

        return retval;
}
