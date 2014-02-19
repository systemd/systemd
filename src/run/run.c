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

#include <stdio.h>
#include <getopt.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "strv.h"
#include "build.h"
#include "unit-name.h"
#include "path-util.h"
#include "bus-error.h"

static bool arg_scope = false;
static bool arg_remain_after_exit = false;
static const char *arg_unit = NULL;
static const char *arg_description = NULL;
static const char *arg_slice = NULL;
static bool arg_send_sighup = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_user = false;
static const char *arg_service_type = NULL;
static const char *arg_exec_user = NULL;
static const char *arg_exec_group = NULL;
static int arg_nice = 0;
static bool arg_nice_set = false;
static char **arg_environment = NULL;

static int help(void) {

        printf("%s [OPTIONS...] COMMAND [ARGS...]\n\n"
               "Run the specified command in a transient scope or service unit.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --user               Run as user unit\n"
               "  -H --host=[USER@]HOST   Operate on remote host\n"
               "  -M --machine=CONTAINER  Operate on local container\n"
               "     --scope              Run this as scope rather than service\n"
               "     --unit=UNIT          Run under the specified unit name\n"
               "     --description=TEXT   Description for unit\n"
               "     --slice=SLICE        Run in the specified slice\n"
               "  -r --remain-after-exit  Leave service around until explicitly stopped\n"
               "     --send-sighup        Send SIGHUP when terminating\n"
               "     --service-type=TYPE  Service type\n"
               "     --uid=USER           Run as system user\n"
               "     --gid=GROUP          Run as system group\n"
               "     --nice=NICE          Nice level\n"
               "     --setenv=NAME=VALUE  Set environment\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_SCOPE,
                ARG_UNIT,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SEND_SIGHUP,
                ARG_EXEC_USER,
                ARG_EXEC_GROUP,
                ARG_SERVICE_TYPE,
                ARG_NICE,
                ARG_SETENV
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'              },
                { "version",           no_argument,       NULL, ARG_VERSION      },
                { "user",              no_argument,       NULL, ARG_USER         },
                { "system",            no_argument,       NULL, ARG_SYSTEM       },
                { "scope",             no_argument,       NULL, ARG_SCOPE        },
                { "unit",              required_argument, NULL, ARG_UNIT         },
                { "description",       required_argument, NULL, ARG_DESCRIPTION  },
                { "slice",             required_argument, NULL, ARG_SLICE        },
                { "remain-after-exit", no_argument,       NULL, 'r'              },
                { "send-sighup",       no_argument,       NULL, ARG_SEND_SIGHUP  },
                { "host",              required_argument, NULL, 'H'              },
                { "machine",           required_argument, NULL, 'M'              },
                { "service-type",      required_argument, NULL, ARG_SERVICE_TYPE },
                { "uid",               required_argument, NULL, ARG_EXEC_USER    },
                { "gid",               required_argument, NULL, ARG_EXEC_GROUP   },
                { "nice",              required_argument, NULL, ARG_NICE         },
                { "setenv",            required_argument, NULL, ARG_SETENV       },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hrH:M:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case ARG_SCOPE:
                        arg_scope = true;
                        break;

                case ARG_UNIT:
                        arg_unit = optarg;
                        break;

                case ARG_DESCRIPTION:
                        arg_description = optarg;
                        break;

                case ARG_SLICE:
                        arg_slice = optarg;
                        break;

                case ARG_SEND_SIGHUP:
                        arg_send_sighup = true;
                        break;

                case 'r':
                        arg_remain_after_exit = true;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_CONTAINER;
                        arg_host = optarg;
                        break;

                case ARG_SERVICE_TYPE:
                        arg_service_type = optarg;
                        break;

                case ARG_EXEC_USER:
                        arg_exec_user = optarg;
                        break;

                case ARG_EXEC_GROUP:
                        arg_exec_group = optarg;
                        break;

                case ARG_NICE:
                        r = safe_atoi(optarg, &arg_nice);
                        if (r < 0) {
                                log_error("Failed to parse nice value");
                                return -EINVAL;
                        }

                        arg_nice_set = true;
                        break;

                case ARG_SETENV:

                        if (strv_extend(&arg_environment, optarg) < 0)
                                return log_oom();

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind >= argc) {
                log_error("Command line to execute required.");
                return -EINVAL;
        }

        if (arg_user && arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Execution in user context is not supported on non-local systems.");
                return -EINVAL;
        }

        if (arg_scope && arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Scope execution is not supported on non-local systems.");
                return -EINVAL;
        }

        if (arg_scope && (arg_remain_after_exit || arg_service_type || arg_exec_user || arg_exec_group || arg_nice_set || arg_environment)) {
                log_error("--remain-after-exit, --service-type=, --user=, --group=, --nice= and --setenv= are not supported in --scope mode.");
                return -EINVAL;
        }

        return 1;
}

static int message_start_transient_unit_new(sd_bus *bus, const char *name, sd_bus_message **ret) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(ret);

        log_info("Running as unit %s.", name);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", name, "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
        if (r < 0)
                return r;

        if (!isempty(arg_slice)) {
                _cleanup_free_ char *slice;

                slice = unit_name_mangle_with_suffix(arg_slice, MANGLE_NOGLOB, ".slice");
                if (!slice)
                        return -ENOMEM;

                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", arg_send_sighup);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

static int message_start_transient_unit_send(sd_bus *bus, sd_bus_message *m, sd_bus_error *error, sd_bus_message **reply) {
        int r;

        assert(bus);
        assert(m);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        return sd_bus_call(bus, m, 0, error, reply);
}

static int start_transient_service(
                sd_bus *bus,
                char **argv,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, MANGLE_NOGLOB, ".service");
        else
                asprintf(&name, "run-%lu.service", (unsigned long) getpid());
        if (!name)
                return -ENOMEM;

        r = message_start_transient_unit_new(bus, name, &m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "RemainAfterExit", "b", arg_remain_after_exit);
        if (r < 0)
                return r;

        if (arg_service_type) {
                r = sd_bus_message_append(m, "(sv)", "Type", "s", arg_service_type);
                if (r < 0)
                        return r;
        }

        if (arg_exec_user) {
                r = sd_bus_message_append(m, "(sv)", "User", "s", arg_exec_user);
                if (r < 0)
                        return r;
        }

        if (arg_exec_group) {
                r = sd_bus_message_append(m, "(sv)", "Group", "s", arg_exec_group);
                if (r < 0)
                        return r;
        }

        if (arg_nice_set) {
                r = sd_bus_message_append(m, "(sv)", "Nice", "i", arg_nice);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(arg_environment)) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", "Environment");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(m, arg_environment);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", "ExecStart");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'v', "a(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'r', "sasb");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", argv[0]);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(m, argv);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "b", false);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        return message_start_transient_unit_send(bus, m, error, NULL);
}

static int start_transient_scope(
                sd_bus *bus,
                char **argv,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(bus);

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, MANGLE_NOGLOB, ".scope");
        else
                asprintf(&name, "run-%lu.scope", (unsigned long) getpid());
        if (!name)
                return -ENOMEM;

        r = message_start_transient_unit_new(bus, name, &m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, (uint32_t) getpid());
        if (r < 0)
                return r;

        r = message_start_transient_unit_send(bus, m, error, NULL);
        if (r < 0)
                return r;

        execvp(argv[0], argv);
        log_error("Failed to execute: %m");
        return -errno;
}

int main(int argc, char* argv[]) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *description = NULL, *command = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = find_binary(argv[optind], &command);
        if (r < 0) {
                log_error("Failed to find executable %s: %s", argv[optind], strerror(-r));
                goto finish;
        }
        argv[optind] = command;

        if (!arg_description) {
                description = strv_join(argv + optind, " ");
                if (!description) {
                        r = log_oom();
                        goto finish;
                }

                arg_description = description;
        }

        r = bus_open_transport(arg_transport, arg_host, arg_user, &bus);
        if (r < 0) {
                log_error("Failed to create bus connection: %s", strerror(-r));
                goto finish;
        }

        if (arg_scope)
                r = start_transient_scope(bus, argv + optind, &error);
        else
                r = start_transient_service(bus, argv + optind, &error);
        if (r < 0)
                log_error("Failed start transient unit: %s", bus_error_message(&error, r));

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
