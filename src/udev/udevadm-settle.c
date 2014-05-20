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
#include <sys/inotify.h>
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
        int rc = EXIT_FAILURE, c;

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
                        exit(EXIT_SUCCESS);
                case '?':
                        exit(EXIT_FAILURE);
                default:
                        assert_not_reached("Unknown argument");
                }
        }

        if (optind < argc) {
                fprintf(stderr, "Extraneous argument: '%s'\n", argv[optind]);
                exit(EXIT_FAILURE);
        }

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                struct udev_ctrl *uctrl;

                uctrl = udev_ctrl_new(udev);
                if (uctrl != NULL) {
                        if (udev_ctrl_send_ping(uctrl, timeout) < 0) {
                                log_debug("no connection to daemon");
                                udev_ctrl_unref(uctrl);
                                rc = EXIT_SUCCESS;
                                goto out;
                        }
                        udev_ctrl_unref(uctrl);
                }
        }

        pfd[0].events = POLLIN;
        pfd[0].fd = inotify_init1(IN_CLOEXEC);
        if (pfd[0].fd < 0) {
                log_error("inotify_init failed: %m");
                goto out;
        }

        if (inotify_add_watch(pfd[0].fd, "/run/udev/queue" , IN_DELETE) < 0) {
                /* If it does not exist, we don't have to wait */
                if (errno == ENOENT)
                        rc = EXIT_SUCCESS;
                else
                        log_debug("watching /run/udev/queue failed");
                goto out;
        }

        for (;;) {
                if (exists && access(exists, F_OK) >= 0) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                /* exit if queue is empty */
                if (access("/run/udev/queue", F_OK) < 0) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                /* wake up when "queue" file is deleted */
                if (poll(pfd, 1, 100) > 0 && pfd[0].revents & POLLIN) {
                        char buf[sizeof(struct inotify_event) + PATH_MAX];

                        read(pfd[0].fd, buf, sizeof(buf));
                }
        }

out:
        if (pfd[0].fd >= 0)
                close(pfd[0].fd);
        return rc;
}

const struct udevadm_cmd udevadm_settle = {
        .name = "settle",
        .cmd = adm_settle,
        .help = "wait for pending udev events",
};
