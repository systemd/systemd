/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <stddef.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "build.h"
#include "strv.h"
#include "def.h"

static const char *arg_address = DEFAULT_SYSTEM_BUS_PATH;
static char *arg_command_line_buffer = NULL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Connect STDIO or a socket to a given bus address.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --address=ADDRESS   Connect to the bus specified by ADDRESS\n"
               "                         (default: " DEFAULT_SYSTEM_BUS_PATH ")\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ADDRESS,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "address",    required_argument, NULL, ARG_ADDRESS    },
                { NULL,         0,                 NULL, 0              }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_ADDRESS:
                        arg_address = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        /* If the first command line argument is only "x" characters
         * we'll write who we are talking to into it, so that "ps" is
         * explanatory */
        arg_command_line_buffer = argv[optind];
        if (argc > optind + 1 ||
            (arg_command_line_buffer && arg_command_line_buffer[strspn(arg_command_line_buffer, "x")] != 0)) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        return 1;
}

static int rename_service(sd_bus *a, sd_bus *b) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        _cleanup_free_ char *p = NULL, *name = NULL;
        const char *comm;
        char **cmdline;
        uid_t uid;
        pid_t pid;
        int r;

        assert(a);
        assert(b);

        r = sd_bus_get_peer_creds(b, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_COMM, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pid(creds, &pid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_cmdline(creds, &cmdline);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_comm(creds, &comm);
        if (r < 0)
                return r;

        name = uid_to_name(uid);
        if (!name)
                return -ENOMEM;

        p = strv_join(cmdline, " ");
        if (!p)
                return -ENOMEM;

        /* The status string gets the full command line ... */
        sd_notifyf(false,
                   "STATUS=Processing requests from client PID "PID_FMT" (%s); UID "UID_FMT" (%s)",
                   pid, p,
                   uid, name);

        /* ... and the argv line only the short comm */
        if (arg_command_line_buffer) {
                size_t m, w;

                m = strlen(arg_command_line_buffer);
                w = snprintf(arg_command_line_buffer, m,
                             "[PID "PID_FMT"/%s; UID "UID_FMT"/%s]",
                             pid, comm,
                             uid, name);

                if (m > w)
                        memzero(arg_command_line_buffer + w, m - w);
        }

        log_debug("Running on behalf of PID "PID_FMT" (%s), UID "UID_FMT" (%s), %s",
                  pid, p,
                  uid, name,
                  a->unique_name);
                ;
        return 0;
}

static int synthesize_name_acquired(sd_bus *a, sd_bus *b, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        const char *name, *old_owner, *new_owner;
        int r;

        assert(a);
        assert(b);
        assert(m);

        /* If we get NameOwnerChanged for our own name, we need to
         * synthesize NameLost/NameAcquired, since socket clients need
         * that, even though it is obsoleted on kdbus */

        if (!a->is_kernel)
                return 0;

        if (!sd_bus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged") ||
            !streq_ptr(m->path, "/org/freedesktop/DBus") ||
            !streq_ptr(m->sender, "org.freedesktop.DBus"))
                return 0;

        r = sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner);
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        if (streq(old_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameLost");

        } else if (streq(new_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameAcquired");
        } else
                return 0;

        if (r < 0)
                return r;

        r = sd_bus_message_append(n, "s", name);
        if (r < 0)
                return r;

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(b, n);
        if (r < 0)
                return r;

        return sd_bus_send(b, n, NULL);
}

static int process_policy(sd_bus *a, sd_bus *b, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        int r;

        assert(a);
        assert(b);
        assert(m);

        if (!sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "GetAll"))
                return 0;

        if (!streq_ptr(m->path, "/org/gnome/DisplayManager/Slave"))
                return 0;

        r = sd_bus_message_new_method_errorf(m, &n, SD_BUS_ERROR_ACCESS_DENIED, "gdm, you are stupid");
        if (r < 0)
                return r;

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0) {
                log_error("Failed to append sender to gdm reply: %s", strerror(-r));
                return r;
        }

        r = bus_seal_synthetic_message(b, n);
        if (r < 0) {
                log_error("Failed to seal gdm reply: %s", strerror(-r));
                return r;
        }

        r = sd_bus_send(b, n, NULL);
        if (r < 0) {
                log_error("Failed to send gdm reply: %s", strerror(-r));
                return r;
        }

        return 1;
}

static int process_hello(sd_bus *a, sd_bus *b, sd_bus_message *m, bool *got_hello) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        bool is_hello;
        int r;

        assert(a);
        assert(b);
        assert(m);
        assert(got_hello);

        /* As reaction to hello we need to respond with two messages:
         * the callback reply and the NameAcquired for the unique
         * name, since hello is otherwise obsolete on kdbus. */

        is_hello =
                sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "Hello") &&
                streq_ptr(m->destination, "org.freedesktop.DBus");

        if (!is_hello) {

                if (*got_hello)
                        return 0;

                log_error("First packet isn't hello (it's %s.%s), aborting.", m->interface, m->member);
                return -EIO;
        }

        if (*got_hello) {
                log_error("Got duplicate hello, aborting.");
                return -EIO;
        }

        *got_hello = true;

        if (!a->is_kernel)
                return 0;

        r = sd_bus_message_new_method_return(m, &n);
        if (r < 0) {
                log_error("Failed to generate HELLO reply: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_append(n, "s", a->unique_name);
        if (r < 0) {
                log_error("Failed to append unique name to HELLO reply: %s", strerror(-r));
                return r;
        }

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0) {
                log_error("Failed to append sender to HELLO reply: %s", strerror(-r));
                return r;
        }

        r = bus_seal_synthetic_message(b, n);
        if (r < 0) {
                log_error("Failed to seal HELLO reply: %s", strerror(-r));
                return r;
        }

        r = sd_bus_send(b, n, NULL);
        if (r < 0) {
                log_error("Failed to send HELLO reply: %s", strerror(-r));
                return r;
        }

        n = sd_bus_message_unref(n);
        r = sd_bus_message_new_signal(
                        b,
                        &n,
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameAcquired");
        if (r < 0) {
                log_error("Failed to allocate initial NameAcquired message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_append(n, "s", a->unique_name);
        if (r < 0) {
                log_error("Failed to append unique name to NameAcquired message: %s", strerror(-r));
                return r;
        }

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0) {
                log_error("Failed to append sender to NameAcquired message: %s", strerror(-r));
                return r;
        }

        r = bus_seal_synthetic_message(b, n);
        if (r < 0) {
                log_error("Failed to seal NameAcquired message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_send(b, n, NULL);
        if (r < 0) {
                log_error("Failed to send NameAcquired message: %s", strerror(-r));
                return r;
        }

        return 1;
}

static int patch_sender(sd_bus *a, sd_bus_message *m) {
        char **well_known = NULL;
        sd_bus_creds *c;
        int r;

        assert(a);
        assert(m);

        if (!a->is_kernel)
                return 0;

        /* We will change the sender of messages from the bus driver
         * so that they originate from the bus driver. This is a
         * speciality originating from dbus1, where the bus driver did
         * not have a unique id, but only the well-known name. */

        c = sd_bus_message_get_creds(m);
        if (!c)
                return 0;

        r = sd_bus_creds_get_well_known_names(c, &well_known);
        if (r < 0)
                return r;

        if (strv_contains(well_known, "org.freedesktop.DBus"))
                m->sender = "org.freedesktop.DBus";

        return 0;
}

int main(int argc, char *argv[]) {

        _cleanup_bus_unref_ sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        int r, in_fd, out_fd;
        bool got_hello = false;
        bool is_unix;
        struct ucred ucred = {};
        _cleanup_free_ char *peersec = NULL;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_listen_fds(0);
        if (r == 0) {
                in_fd = STDIN_FILENO;
                out_fd = STDOUT_FILENO;
        } else if (r == 1) {
                in_fd = SD_LISTEN_FDS_START;
                out_fd = SD_LISTEN_FDS_START;
        } else {
                log_error("Illegal number of file descriptors passed");
                goto finish;
        }

        is_unix =
                sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        if (is_unix) {
                getpeercred(in_fd, &ucred);
                getpeersec(in_fd, &peersec);
        }

        r = sd_bus_new(&a);
        if (r < 0) {
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_name(a, "sd-proxy");
        if (r < 0) {
                log_error("Failed to set bus name: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_address(a, arg_address);
        if (r < 0) {
                log_error("Failed to set address to connect to: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_negotiate_fds(a, is_unix);
        if (r < 0) {
                log_error("Failed to set FD negotiation: %s", strerror(-r));
                goto finish;
        }

        if (ucred.pid > 0) {
                a->fake_creds.pid = ucred.pid;
                a->fake_creds.uid = ucred.uid;
                a->fake_creds.gid = ucred.gid;
                a->fake_creds_valid = true;
        }

        if (peersec) {
                a->fake_label = peersec;
                peersec = NULL;
        }

        a->manual_peer_interface = true;

        r = sd_bus_start(a);
        if (r < 0) {
                log_error("Failed to start bus client: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_get_server_id(a, &server_id);
        if (r < 0) {
                log_error("Failed to get server ID: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_new(&b);
        if (r < 0) {
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_fd(b, in_fd, out_fd);
        if (r < 0) {
                log_error("Failed to set fds: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_server(b, 1, server_id);
        if (r < 0) {
                log_error("Failed to set server mode: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_negotiate_fds(b, is_unix);
        if (r < 0) {
                log_error("Failed to set FD negotiation: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_anonymous(b, true);
        if (r < 0) {
                log_error("Failed to set anonymous authentication: %s", strerror(-r));
                goto finish;
        }

        b->manual_peer_interface = true;

        r = sd_bus_start(b);
        if (r < 0) {
                log_error("Failed to start bus client: %s", strerror(-r));
                goto finish;
        }

        r = rename_service(a, b);
        if (r < 0)
                log_debug("Failed to rename process: %s", strerror(-r));

        if (a->is_kernel) {
                _cleanup_free_ char *match = NULL;
                const char *unique;

                r = sd_bus_get_unique_name(a, &unique);
                if (r < 0) {
                        log_error("Failed to get unique name: %s", strerror(-r));
                        goto finish;
                }

                match = strjoin("type='signal',"
                                "sender='org.freedesktop.DBus',"
                                "path='/org/freedesktop/DBus',"
                                "interface='org.freedesktop.DBus',"
                                "member='NameOwnerChanged',"
                                "arg1='",
                                unique,
                                "'",
                                NULL);
                if (!match) {
                        log_oom();
                        goto finish;
                }

                r = sd_bus_add_match(a, match, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to add match for NameLost: %s", strerror(-r));
                        goto finish;
                }

                free(match);
                match = strjoin("type='signal',"
                                "sender='org.freedesktop.DBus',"
                                "path='/org/freedesktop/DBus',"
                                "interface='org.freedesktop.DBus',"
                                "member='NameOwnerChanged',"
                                "arg2='",
                                unique,
                                "'",
                                NULL);
                if (!match) {
                        log_oom();
                        goto finish;
                }

                r = sd_bus_add_match(a, match, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to add match for NameAcquired: %s", strerror(-r));
                        goto finish;
                }
        }

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                int events_a, events_b, fd;
                uint64_t timeout_a, timeout_b, t;
                struct timespec _ts, *ts;
                struct pollfd *pollfd;
                int k;

                if (got_hello) {
                        r = sd_bus_process(a, &m);
                        if (r < 0) {
                                /* treat 'connection reset by peer' as clean exit condition */
                                if (r == -ECONNRESET)
                                        r = 0;
                                else
                                        log_error("Failed to process bus a: %s", strerror(-r));

                                goto finish;
                        }

                        if (m) {
                                /* We officially got EOF, let's quit */
                                if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected")) {
                                        r = 0;
                                        goto finish;
                                }

                                k = synthesize_name_acquired(a, b, m);
                                if (k < 0) {
                                        r = k;
                                        log_error("Failed to synthesize message: %s", strerror(-r));
                                        goto finish;
                                }

                                patch_sender(a, m);

                                k = sd_bus_send(b, m, NULL);
                                if (k < 0) {
                                        if (k == -ECONNRESET)
                                                r = 0;
                                        else {
                                                r = k;
                                                log_error("Failed to send message: %s", strerror(-r));
                                        }

                                        goto finish;
                                }
                        }

                        if (r > 0)
                                continue;
                }

                r = sd_bus_process(b, &m);
                if (r < 0) {
                        /* treat 'connection reset by peer' as clean exit condition */
                        if (r == -ECONNRESET)
                                r = 0;
                        else
                                log_error("Failed to process bus b: %s", strerror(-r));

                        goto finish;
                }

                if (m) {
                        /* We officially got EOF, let's quit */
                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected")) {
                                r = 0;
                                goto finish;
                        }

                        k = process_hello(a, b, m, &got_hello);
                        if (k < 0) {
                                r = k;
                                log_error("Failed to process HELLO: %s", strerror(-r));
                                goto finish;
                        }

                        if (k > 0)
                                r = k;
                        else {
                                k = process_policy(a, b, m);
                                if (k < 0) {
                                        r = k;
                                        log_error("Failed to process policy: %s", strerror(-r));
                                        goto finish;
                                }

                                k = sd_bus_send(a, m, NULL);
                                if (k < 0) {
                                        if (r == -ECONNRESET)
                                                r = 0;
                                        else {
                                                r = k;
                                                log_error("Failed to send message: %s", strerror(-r));
                                        }

                                        goto finish;
                                }
                        }
                }

                if (r > 0)
                        continue;

                fd = sd_bus_get_fd(a);
                if (fd < 0) {
                        log_error("Failed to get fd: %s", strerror(-r));
                        goto finish;
                }

                events_a = sd_bus_get_events(a);
                if (events_a < 0) {
                        log_error("Failed to get events mask: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_get_timeout(a, &timeout_a);
                if (r < 0) {
                        log_error("Failed to get timeout: %s", strerror(-r));
                        goto finish;
                }

                events_b = sd_bus_get_events(b);
                if (events_b < 0) {
                        log_error("Failed to get events mask: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_get_timeout(b, &timeout_b);
                if (r < 0) {
                        log_error("Failed to get timeout: %s", strerror(-r));
                        goto finish;
                }

                t = timeout_a;
                if (t == (uint64_t) -1 || (timeout_b != (uint64_t) -1 && timeout_b < timeout_a))
                        t = timeout_b;

                if (t == (uint64_t) -1)
                        ts = NULL;
                else {
                        usec_t nw;

                        nw = now(CLOCK_MONOTONIC);
                        if (t > nw)
                                t -= nw;
                        else
                                t = 0;

                        ts = timespec_store(&_ts, t);
                }

                pollfd = (struct pollfd[3]) {
                        {.fd = fd,     .events = events_a,           },
                        {.fd = in_fd,  .events = events_b & POLLIN,  },
                        {.fd = out_fd, .events = events_b & POLLOUT, }
                };

                r = ppoll(pollfd, 3, ts, NULL);
                if (r < 0) {
                        log_error("ppoll() failed: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        sd_bus_flush(a);
        sd_bus_flush(b);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
