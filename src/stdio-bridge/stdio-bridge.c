/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "errno-util.h"
#include "log.h"
#include "main-func.h"
#include "util.h"

#define DEFAULT_BUS_PATH "unix:path=/run/dbus/system_bus_socket"

static const char *arg_bus_path = DEFAULT_BUS_PATH;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "STDIO or socket-activatable proxy to a given DBus endpoint.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "  -p --bus-path=PATH     Path to the kernel bus (default: %s)\n"
               "  -M --machine=MACHINE   Name of machine to connect to\n",
               program_invocation_short_name, DEFAULT_BUS_PATH);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_MACHINE,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'         },
                { "version",         no_argument,       NULL, ARG_VERSION },
                { "bus-path",        required_argument, NULL, 'p'         },
                { "machine",         required_argument, NULL, 'M'         },
                {},
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:M:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'p':
                        arg_bus_path = optarg;
                        break;

                case 'M':
                        arg_bus_path = optarg;
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unknown option code %c", c);
                }
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        bool is_unix;
        int r, in_fd, out_fd;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Illegal number of file descriptors passed.");

        is_unix =
                sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        r = sd_bus_new(&a);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        if (arg_transport == BUS_TRANSPORT_MACHINE)
                r = bus_set_address_system_machine(a, arg_bus_path);
        else
                r = sd_bus_set_address(a, arg_bus_path);
        if (r < 0)
                return log_error_errno(r, "Failed to set address to connect to: %m");

        r = sd_bus_negotiate_fds(a, is_unix);
        if (r < 0)
                return log_error_errno(r, "Failed to set FD negotiation: %m");

        r = sd_bus_start(a);
        if (r < 0)
                return log_error_errno(r, "Failed to start bus client: %m");

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
                return log_error_errno(r, "Failed to start bus client: %m");

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                int events_a, events_b, fd;
                uint64_t timeout_a, timeout_b, t;
                struct timespec _ts, *ts;

                r = sd_bus_process(a, &m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus a: %m");

                if (m) {
                        r = sd_bus_send(b, m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send message: %m");
                }

                if (r > 0)
                        continue;

                r = sd_bus_process(b, &m);
                if (r < 0) {
                        /* treat 'connection reset by peer' as clean exit condition */
                        if (ERRNO_IS_DISCONNECT(r))
                                return 0;

                        return log_error_errno(r, "Failed to process bus: %m");
                }

                if (m) {
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

                {
                        struct pollfd p[3] = {
                                {.fd = fd,            .events = events_a           },
                                {.fd = STDIN_FILENO,  .events = events_b & POLLIN  },
                                {.fd = STDOUT_FILENO, .events = events_b & POLLOUT },
                        };

                        r = ppoll(p, ELEMENTSOF(p), ts, NULL);
                }
                if (r < 0)
                        return log_error_errno(errno, "ppoll() failed: %m");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
