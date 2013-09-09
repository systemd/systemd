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
#include "bus-internal.h"
#include "bus-message.h"
#include "strv.h"
#include "build.h"
#include "unit-name.h"
#include "path-util.h"

static bool arg_scope = false;
static bool arg_user = false;
static bool arg_remain_after_exit = false;
static const char *arg_unit = NULL;
static const char *arg_description = NULL;
static const char *arg_slice = NULL;
static bool arg_send_sighup = false;

static int help(void) {

        printf("%s [OPTIONS...] COMMAND [ARGS...]\n\n"
               "Run the specified command in a transient scope or service unit.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --user               Run as user unit\n"
               "     --scope              Run this as scope rather than service\n"
               "     --unit=UNIT          Run under the specified unit name\n"
               "     --description=TEXT   Description for unit\n"
               "     --slice=SLICE        Run in the specified slice\n"
               "  -r --remain-after-exit  Leave service around until explicitly stopped\n"
               "     --send-sighup        Send SIGHUP when terminating\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SCOPE,
                ARG_UNIT,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SEND_SIGHUP,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'             },
                { "version",           no_argument,       NULL, ARG_VERSION     },
                { "user",              no_argument,       NULL, ARG_USER        },
                { "scope",             no_argument,       NULL, ARG_SCOPE       },
                { "unit",              required_argument, NULL, ARG_UNIT        },
                { "description",       required_argument, NULL, ARG_DESCRIPTION },
                { "slice",             required_argument, NULL, ARG_SLICE       },
                { "remain-after-exit", no_argument,       NULL, 'r'             },
                { "send-sighup",       no_argument,       NULL, ARG_SEND_SIGHUP },
                { NULL,                0,                 NULL, 0               },
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hr", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_user = true;
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

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                log_error("Command line to execute required.");
                return -EINVAL;
        }

        return 1;
}

static int message_start_transient_unit_new(sd_bus *bus, const char *name, sd_bus_message **ret) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        log_info("Running as unit %s.", name);

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit", &m);
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

                slice = unit_name_mangle_with_suffix(arg_slice, ".slice");
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

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        return sd_bus_send_with_reply_and_block(bus, m, 0, error, reply);
}

static int start_transient_service(
                sd_bus *bus,
                char **argv,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *name = NULL;
        char **i;
        int r;

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, ".service");
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

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        STRV_FOREACH(i, argv) {
                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
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

        return  message_start_transient_unit_send(bus, m, error, &reply);
}

static int start_transient_scope(
                sd_bus *bus,
                char **argv,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        if (arg_unit)
                name = unit_name_mangle_with_suffix(arg_unit, ".scope");
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

        r = message_start_transient_unit_send(bus, m, error, &reply);
        if (r < 0)
                return r;

        execvp(argv[0], argv);
        log_error("Failed to execute: %m");
        return -errno;
}

int main(int argc, char* argv[]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *description = NULL, *command = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto fail;

        r = find_binary(argv[optind], &command);
        if (r < 0) {
                log_error("Failed to find executable %s: %s", argv[optind], strerror(-r));
                goto fail;
        }
        argv[optind] = command;

        if (!arg_description) {
                description = strv_join(argv + optind, " ");
                if (!description) {
                        r = log_oom();
                        goto fail;
                }

                arg_description = description;
        }

        if (arg_user)
                r = sd_bus_open_user(&bus);
        else
                r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_error("Failed to create new bus connection: %s", strerror(-r));
                goto fail;
        }

        if (arg_scope)
                r = start_transient_scope(bus, argv + optind, &error);
        else
                r = start_transient_service(bus, argv + optind, &error);
        if (r < 0) {
                log_error("Failed start transient unit: %s", error.message ? error.message : strerror(-r));
                sd_bus_error_free(&error);
                goto fail;
        }

fail:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
