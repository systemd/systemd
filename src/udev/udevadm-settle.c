/*
 * Copyright (C) 2006-2009 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udev-util.h"
#include "util.h"

static void help(void) {
        printf("Usage: udevadm settle OPTIONS\n"
               "  -t,--timeout=<seconds>     maximum time to wait for events\n"
               "  -E,--exit-if-exists=<file> stop waiting if file exists\n"
               "  -h,--help\n\n");
}

static int adm_settle(struct udev *udev, int argc, char *argv[])
{
        static const struct option options[] = {
                { "seq-start",      required_argument, NULL, '\0' }, /* removed */
                { "seq-end",        required_argument, NULL, '\0' }, /* removed */
                { "timeout",        required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                { "quiet",          no_argument,       NULL, 'q' },  /* removed */
                { "help",           no_argument,       NULL, 'h' },
                {}
        };
        const char *exists = NULL;
        unsigned int timeout = 120;
        struct pollfd pfd[1] = { {.fd = -1}, };
        int c;
        struct udev_queue *queue;
        int rc = EXIT_FAILURE;

        while ((c = getopt_long(argc, argv, "s:e:t:E:qh", options, NULL)) >= 0) {
                switch (c) {
                case 't': {
                        int r;

                        r = safe_atou(optarg, &timeout);
                        if (r < 0) {
                                fprintf(stderr, "Invalid timeout value '%s': %s\n",
                                        optarg, strerror(-r));
                                exit(EXIT_FAILURE);
                        };
                        break;
                }
                case 'E':
                        exists = optarg;
                        break;
                case 'h':
                        help();
                        return EXIT_SUCCESS;
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

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                struct udev_ctrl *uctrl;

                uctrl = udev_ctrl_new(udev);
                if (uctrl != NULL) {
                        if (udev_ctrl_send_ping(uctrl, timeout) < 0) {
                                log_debug("no connection to daemon");
                                udev_ctrl_unref(uctrl);
                                return EXIT_SUCCESS;
                        }
                        udev_ctrl_unref(uctrl);
                }
        }

        queue = udev_queue_new(udev);
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

                /* wake up when queue is empty */
                if (poll(pfd, 1, MSEC_PER_SEC) > 0 && pfd[0].revents & POLLIN)
                        udev_queue_flush(queue);
        }

out:
        udev_queue_unref(queue);
        return rc;
}

const struct udevadm_cmd udevadm_settle = {
        .name = "settle",
        .cmd = adm_settle,
        .help = "wait for pending udev events",
};
