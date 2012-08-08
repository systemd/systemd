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

#include <getopt.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <dbus.h>
#include <unistd.h>

#include "dbus-common.h"
#include "util.h"
#include "build.h"
#include "strv.h"

static const char* arg_what = "idle:sleep:shutdown";
static const char* arg_who = NULL;
static const char* arg_why = "Unknown reason";
static const char* arg_mode = "block";

static enum {
        ACTION_INHIBIT,
        ACTION_LIST
} arg_action = ACTION_INHIBIT;

static int inhibit(DBusConnection *bus, DBusError *error) {
        DBusMessage *reply = NULL;
        int fd;

        fd = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "Inhibit",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &arg_what,
                        DBUS_TYPE_STRING, &arg_who,
                        DBUS_TYPE_STRING, &arg_why,
                        DBUS_TYPE_STRING, &arg_mode,
                        DBUS_TYPE_INVALID);
        if (fd)
                return fd;

        if (!dbus_message_get_args(reply, error,
                                   DBUS_TYPE_UNIX_FD, &fd,
                                   DBUS_TYPE_INVALID))
                fd = -EIO;

        dbus_message_unref(reply);

        return fd;
}

static int print_inhibitors(DBusConnection *bus, DBusError *error) {
        DBusMessage *reply;
        unsigned n = 0;
        DBusMessageIter iter, sub, sub2;
        int r;

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListInhibitors",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
                return -ENOMEM;
                goto finish;

        if (!dbus_message_iter_init(reply, &iter)) {
                r = -ENOMEM;
                goto finish;
        }

        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
                r = -EIO;
                goto finish;
        }
        dbus_message_iter_recurse(&iter, &sub);

        printf("%-21s %-20s %-20s %-5s %6s %6s\n",
               "WHAT",
               "WHO",
               "WHY",
               "MODE",
               "UID",
               "PID");


        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *what, *who, *why, *mode;
                char *ewho, *ewhy;
                dbus_uint32_t uid, pid;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &what, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &who, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &why, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &mode, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &pid, false) < 0) {
                        r = -EIO;
                        goto finish;
                }

                ewho = ellipsize(who, 20, 66);
                ewhy = ellipsize(why, 20, 66);

                printf("%-21s %-20s %-20s %-5s %6lu %6lu\n",
                       what, ewho ? ewho : who, ewhy ? ewhy : why, mode, (unsigned long) uid, (unsigned long) pid);

                free(ewho);
                free(ewhy);

                dbus_message_iter_next(&sub);

                n++;
        }

        printf("\n%u inhibitors listed.\n", n);
        r = 0;

finish:
        if (reply)
                dbus_message_unref(reply);

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Execute a process while inhibiting shutdown/sleep/idle.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --what=WHAT          Operations to inhibit, colon separated list of idle,\n"
               "                          sleep, shutdown\n"
               "     --who=STRING         A descriptive string who is inhibiting\n"
               "     --why=STRING         A descriptive string why is being inhibited\n"
               "     --mode=MODE          One of block or delay\n"
               "     --list               List active inhibitors\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_WHAT,
                ARG_WHO,
                ARG_WHY,
                ARG_MODE,
                ARG_LIST,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "what",         required_argument, NULL, ARG_WHAT         },
                { "who",          required_argument, NULL, ARG_WHO          },
                { "why",          required_argument, NULL, ARG_WHY          },
                { "mode",         required_argument, NULL, ARG_MODE         },
                { "list",         no_argument,       NULL, ARG_LIST         },
                { NULL,           0,                 NULL, 0                }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_WHAT:
                        arg_what = optarg;
                        break;

                case ARG_WHO:
                        arg_who = optarg;
                        break;

                case ARG_WHY:
                        arg_why = optarg;
                        break;

                case ARG_MODE:
                        arg_mode = optarg;
                        break;

                case ARG_LIST:
                        arg_action = ACTION_LIST;
                        break;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (arg_action == ACTION_INHIBIT && optind >= argc) {
                log_error("Missing command line to execute.");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, exit_code = 0;
        DBusConnection *bus = NULL;
        DBusError error;
        int fd = -1;

        dbus_error_init(&error);

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!bus) {
                log_error("Failed to connect to bus: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (arg_action == ACTION_LIST) {

                r = print_inhibitors(bus, &error);
                if (r < 0) {
                        log_error("Failed to list inhibitors: %s", bus_error_message_or_strerror(&error, -r));
                        goto finish;
                }

        } else {
                char *w = NULL;
                pid_t pid;

                if (!arg_who)
                        arg_who = w = strv_join(argv + optind, " ");

                fd = inhibit(bus, &error);
                free(w);

                if (fd < 0) {
                        log_error("Failed to inhibit: %s", bus_error_message_or_strerror(&error, -r));
                        r = fd;
                        goto finish;
                }

                pid = fork();
                if (pid < 0) {
                        log_error("Failed to fork: %m");
                        r = -errno;
                        goto finish;
                }

                if (pid == 0) {
                        /* Child */

                        close_nointr_nofail(fd);
                        execvp(argv[optind], argv + optind);
                        log_error("Failed to execute %s: %m", argv[optind]);
                        _exit(EXIT_FAILURE);
                }

                r = wait_for_terminate_and_warn(argv[optind], pid);
                if (r >= 0)
                        exit_code = r;
        }

finish:
        if (bus) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r < 0 ? EXIT_FAILURE : exit_code;
}
