/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "time-util.h"
#include "udevadm.h"
#include "udev.h"

static usec_t arg_timeout = 120 * USEC_PER_SEC;
static const char *arg_exists = NULL;

static int help(void) {
        printf("%s settle [OPTIONS]\n\n"
               "Wait for pending udev events.\n\n"
               "  -h --help                 Show this help\n"
               "  -V --version              Show package version\n"
               "  -t --timeout=SEC          Maximum time to wait for events\n"
               "  -E --exit-if-exists=FILE  Stop waiting if file exists\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "timeout",        required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                { "version",        no_argument,       NULL, 'V' },
                { "help",           no_argument,       NULL, 'h' },
                { "seq-start",      required_argument, NULL, 's' }, /* removed */
                { "seq-end",        required_argument, NULL, 'e' }, /* removed */
                { "quiet",          no_argument,       NULL, 'q' }, /* removed */
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "t:E:Vhs:e:q", options, NULL)) >= 0) {
                switch (c) {
                case 't':
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                        break;
                case 'E':
                        arg_exists = optarg;
                        break;
                case 'V':
                        return version();
                case 'h':
                        return help();
                case 's':
                case 'e':
                case 'q':
                        log_info("Option -%c no longer supported.", c);
                        return -EINVAL;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option.");
                }
        }

        return 1;
}

int settle_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_queue_unrefp) struct udev_queue *queue = NULL;
        struct pollfd pfd;
        usec_t deadline;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        deadline = now(CLOCK_MONOTONIC) + arg_timeout;

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                _cleanup_(udev_ctrl_unrefp) struct udev_ctrl *uctrl = NULL;

                uctrl = udev_ctrl_new();
                if (uctrl) {
                        r = udev_ctrl_send_ping(uctrl, MAX(5U, arg_timeout / USEC_PER_SEC));
                        if (r < 0) {
                                log_debug_errno(r, "Failed to connect to udev daemon.");
                                return 0;
                        }
                }
        }

        queue = udev_queue_new(NULL);
        if (!queue)
                return log_error_errno(errno, "Failed to get udev queue: %m");

        r = udev_queue_get_fd(queue);
        if (r < 0) {
                log_debug_errno(r, "Queue is empty, nothing to watch.");
                return 0;
        }

        pfd = (struct pollfd) {
                .events = POLLIN,
                .fd = r,
        };

        for (;;) {
                if (arg_exists && access(arg_exists, F_OK) >= 0)
                        return 0;

                /* exit if queue is empty */
                if (udev_queue_get_queue_is_empty(queue))
                        return 0;

                if (now(CLOCK_MONOTONIC) >= deadline)
                        return -ETIMEDOUT;

                /* wake up when queue becomes empty */
                if (poll(&pfd, 1, MSEC_PER_SEC) > 0 && pfd.revents & POLLIN) {
                        r = udev_queue_flush(queue);
                        if (r < 0)
                                return log_error_errno(r, "Failed to flush queue: %m");
                }
        }
}
