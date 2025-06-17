/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <poll.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "build.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "errno-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "time-util.h"

static const char *arg_bus_path = DEFAULT_SYSTEM_BUS_ADDRESS;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Forward messages between a pipe or socket and a D-Bus bus.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "  -p --bus-path=PATH     Path to the bus address (default: %s)\n"
               "     --system            Connect to system bus\n"
               "     --user              Connect to user bus\n"
               "  -M --machine=CONTAINER Name of local container to connect to\n",
               program_invocation_short_name, DEFAULT_SYSTEM_BUS_ADDRESS);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'         },
                { "version",         no_argument,       NULL, ARG_VERSION },
                { "bus-path",        required_argument, NULL, 'p'         },
                { "user",            no_argument,       NULL, ARG_USER    },
                { "system",          no_argument,       NULL, ARG_SYSTEM  },
                { "machine",         required_argument, NULL, 'M'         },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:M:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case 'p':
                        arg_bus_path = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_bus_path, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        bool is_unix;
        int r, in_fd, out_fd;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_listen_fds(0);
        if (r == 0) {
                in_fd = STDIN_FILENO;
                out_fd = STDOUT_FILENO;
        } else if (r == 1) {
                in_fd = SD_LISTEN_FDS_START;
                out_fd = SD_LISTEN_FDS_START;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "More than one file descriptor was passed.");

        is_unix =
                sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        r = sd_bus_new(&a);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        if (arg_transport == BUS_TRANSPORT_MACHINE)
                r = bus_set_address_machine(a, arg_runtime_scope, arg_bus_path);
        else
                r = sd_bus_set_address(a, arg_bus_path);
        if (r < 0)
                return log_error_errno(r, "Failed to set address to connect to: %m");

        r = sd_bus_negotiate_fds(a, is_unix);
        if (r < 0)
                return log_error_errno(r, "Failed to set FD negotiation: %m");

        r = sd_bus_start(a);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        r = sd_bus_get_bus_id(a, &server_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get server ID: %m");

        r = sd_bus_new(&b);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        r = sd_bus_set_fd(b, in_fd, out_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set fds: %m");

        r = sd_bus_set_server(b, 1, server_id);
        if (r < 0)
                return log_error_errno(r, "Failed to set server mode: %m");

        r = sd_bus_negotiate_fds(b, is_unix);
        if (r < 0)
                return log_error_errno(r, "Failed to set FD negotiation: %m");

        r = sd_bus_set_anonymous(b, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set anonymous authentication: %m");

        r = sd_bus_start(b);
        if (r < 0)
                return log_error_errno(r, "Failed to start bus forwarding server: %m");

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                int events_a, events_b, fd;
                usec_t timeout_a, timeout_b, t;

                assert_cc(sizeof(usec_t) == sizeof(uint64_t));

                r = sd_bus_process(a, &m);
                if (ERRNO_IS_NEG_DISCONNECT(r)) /* Treat 'connection reset by peer' as clean exit condition */
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus a: %m");
                if (m) {
                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected"))
                                return 0;

                        r = sd_bus_send(b, m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send message: %m");
                }

                if (r > 0)
                        continue;

                r = sd_bus_process(b, &m);
                if (ERRNO_IS_NEG_DISCONNECT(r)) /* Treat 'connection reset by peer' as clean exit condition */
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus: %m");
                if (m) {
                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected"))
                                return 0;

                        r = sd_bus_send(a, m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send message: %m");
                }

                if (r > 0)
                        continue;

                fd = sd_bus_get_fd(a);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to get fd: %m");

                events_a = sd_bus_get_events(a);
                if (events_a < 0)
                        return log_error_errno(events_a, "Failed to get events mask: %m");

                r = sd_bus_get_timeout(a, &timeout_a);
                if (r < 0)
                        return log_error_errno(r, "Failed to get timeout: %m");

                events_b = sd_bus_get_events(b);
                if (events_b < 0)
                        return log_error_errno(events_b, "Failed to get events mask: %m");

                r = sd_bus_get_timeout(b, &timeout_b);
                if (r < 0)
                        return log_error_errno(r, "Failed to get timeout: %m");

                t = usec_sub_unsigned(MIN(timeout_a, timeout_b), now(CLOCK_MONOTONIC));

                struct pollfd p[3] = {
                        { .fd = fd,     .events = events_a           },
                        { .fd = in_fd,  .events = events_b & POLLIN  },
                        { .fd = out_fd, .events = events_b & POLLOUT },
                };

                r = ppoll_usec(p, ELEMENTSOF(p), t);
                if (r < 0 && !ERRNO_IS_TRANSIENT(r))  /* don't be bothered by signals, i.e. EINTR */
                        return log_error_errno(r, "ppoll() failed: %m");
        }
}

DEFINE_MAIN_FUNCTION(run);
