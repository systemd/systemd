/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "dbus-common.h"
#include "build.h"

static bool arg_no_pager = false;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static const char *arg_host = NULL;

static bool on_tty(void) {
        static int t = -1;

        /* Note that this is invoked relatively early, before we start
         * the pager. That means the value we return reflects whether
         * we originally were started on a tty, not if we currently
         * are. But this is intended, since we want colour and so on
         * when run in our own pager. */

        if (_unlikely_(t < 0))
                t = isatty(STDOUT_FILENO) > 0;

        return t;
}

static void pager_open_if_enabled(void) {
        on_tty();

        if (!arg_no_pager)
                pager_open();
}

static int list_sessions(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        assert(bus);

        pager_open_if_enabled();

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListSessions");
        if (!m) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%10s %10s %-16s %-16s\n", "SESSION", "UID", "USER", "SEAT");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *id, *user, *seat, *object;
                uint32_t uid;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &user, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &seat, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                printf("%10s %10u %-16s %-16s\n", id, (unsigned) uid, user, seat);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u sessions listed.\n", k);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int list_users(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        assert(bus);

        pager_open_if_enabled();

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListUsers");
        if (!m) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%10s %-16s\n", "UID", "USER");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *user, *object;
                uint32_t uid;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &user, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                printf("%10u %-16s\n", (unsigned) uid, user);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u users listed.\n", k);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int list_seats(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        assert(bus);

        pager_open_if_enabled();

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListSeats");
        if (!m) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%-16s\n", "SEAT");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *seat, *object;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &seat, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                printf("%-16s\n", seat);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u seats listed.\n", k);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the login manager.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "  -H --host=[user@]host\n"
               "                      Show information for remote host\n"
               "  -P --privileged     Acquire privileges before execution\n"
               "     --no-pager       Do not pipe output into a pager.\n"
               "Commands:\n"
               "  list-sessions                   List sessions\n"
               "  list-users                      List users\n"
               "  list-seats                      List seats\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "host",      required_argument, NULL, 'H'           },
                { "privileged",no_argument,       NULL, 'P'           },
                { NULL,        0,                 NULL, 0             }
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
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        arg_host = optarg;
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

static int loginctl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

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
                { "list-sessions",         LESS,   1, list_sessions    },
                { "list-users",            EQUAL,  1, list_users       },
                { "list-seats",            EQUAL,  1, list_seats       },
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

        r = loginctl_main(bus, argc, argv, &error);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
        dbus_shutdown();

        pager_close();

        return retval;
}
