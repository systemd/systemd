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

#include "parse-util.h"
#include "udev.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "util.h"

static void help(void) {
        printf("%s settle [OPTIONS]\n\n"
               "Wait for pending udev events.\n\n"
               "  -h --help                 Show this help\n"
               "  -V --version              Show package version\n"
               "  -t --timeout=SECONDS      Maximum time to wait for events\n"
               "  -E --exit-if-exists=FILE  Stop waiting if file exists\n"
               , program_invocation_short_name);
}

int settle_main(int argc, char *argv[], void *userdata) {
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
        usec_t deadline;
        const char *exists = NULL;
        unsigned int timeout = 120;
        struct pollfd pfd[1] = { {.fd = -1}, };
        int c;
        struct udev_queue *queue;
        int rc = EXIT_FAILURE;

        while ((c = getopt_long(argc, argv, "t:E:Vhs:e:q", options, NULL)) >= 0) {
                switch (c) {

                case 't': {
                        int r;

                        r = safe_atou(optarg, &timeout);
                        if (r < 0) {
                                log_error_errno(r, "Invalid timeout value '%s': %m", optarg);
                                return EXIT_FAILURE;
                        }
                        break;
                }

                case 'E':
                        exists = optarg;
                        break;

                case 'V':
                        print_version();
                        return EXIT_SUCCESS;

                case 'h':
                        help();
                        return EXIT_SUCCESS;

                case 's':
                case 'e':
                case 'q':
                        log_info("Option -%c no longer supported.", c);
                        return EXIT_FAILURE;

                case '?':
                        return EXIT_FAILURE;

                default:
                        assert_not_reached("Unknown argument");
                }
        }

        if (optind < argc) {
                fprintf(stderr, "Extraneous argument: '%s'\n", argv[optind]);
                return EXIT_FAILURE;
        }

        deadline = now(CLOCK_MONOTONIC) + timeout * USEC_PER_SEC;

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                struct udev_ctrl *uctrl;

                uctrl = udev_ctrl_new();
                if (uctrl != NULL) {
                        if (udev_ctrl_send_ping(uctrl, MAX(5U, timeout)) < 0) {
                                log_debug("no connection to daemon");
                                udev_ctrl_unref(uctrl);
                                return EXIT_SUCCESS;
                        }
                        udev_ctrl_unref(uctrl);
                }
        }

        queue = udev_queue_new(NULL);
        if (!queue) {
                log_error("unable to get udev queue");
                return EXIT_FAILURE;
        }

        pfd[0].events = POLLIN;
        pfd[0].fd = udev_queue_get_fd(queue);
        if (pfd[0].fd < 0) {
                log_debug("queue is empty, nothing to watch");
                rc = EXIT_SUCCESS;
                goto out;
        }

        for (;;) {
                if (exists && access(exists, F_OK) >= 0) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                /* exit if queue is empty */
                if (udev_queue_get_queue_is_empty(queue)) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                if (now(CLOCK_MONOTONIC) >= deadline)
                        break;

                /* wake up when queue is empty */
                if (poll(pfd, 1, MSEC_PER_SEC) > 0 && pfd[0].revents & POLLIN)
                        udev_queue_flush(queue);
        }

out:
        udev_queue_unref(queue);
        return rc;
}
