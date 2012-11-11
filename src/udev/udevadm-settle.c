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

static int adm_settle(struct udev *udev, int argc, char *argv[])
{
        static const struct option options[] = {
                { "seq-start", required_argument, NULL, 's' },
                { "seq-end", required_argument, NULL, 'e' },
                { "timeout", required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                { "quiet", no_argument, NULL, 'q' },
                { "help", no_argument, NULL, 'h' },
                {}
        };
        usec_t start_usec = now(CLOCK_MONOTONIC);
        usec_t start = 0;
        usec_t end = 0;
        int quiet = 0;
        const char *exists = NULL;
        unsigned int timeout = 120;
        struct pollfd pfd[1] = { {.fd = -1}, };
        struct udev_queue *udev_queue = NULL;
        int rc = EXIT_FAILURE;

        for (;;) {
                int option;
                int seconds;

                option = getopt_long(argc, argv, "s:e:t:E:qh", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 's':
                        start = strtoull(optarg, NULL, 0);
                        break;
                case 'e':
                        end = strtoull(optarg, NULL, 0);
                        break;
                case 't':
                        seconds = atoi(optarg);
                        if (seconds >= 0)
                                timeout = seconds;
                        else
                                fprintf(stderr, "invalid timeout value\n");
                        break;
                case 'q':
                        quiet = 1;
                        break;
                case 'E':
                        exists = optarg;
                        break;
                case 'h':
                        printf("Usage: udevadm settle OPTIONS\n"
                               "  --timeout=<seconds>     maximum time to wait for events\n"
                               "  --seq-start=<seqnum>    first seqnum to wait for\n"
                               "  --seq-end=<seqnum>      last seqnum to wait for\n"
                               "  --exit-if-exists=<file> stop waiting if file exists\n"
                               "  --quiet                 do not print list after timeout\n"
                               "  --help\n\n");
                        exit(EXIT_SUCCESS);
                default:
                        exit(EXIT_FAILURE);
                }
        }

        udev_queue = udev_queue_new(udev);
        if (udev_queue == NULL)
                exit(2);

        if (start > 0) {
                unsigned long long kernel_seq;

                kernel_seq = udev_queue_get_kernel_seqnum(udev_queue);

                /* unless specified, the last event is the current kernel seqnum */
                if (end == 0)
                        end = udev_queue_get_kernel_seqnum(udev_queue);

                if (start > end) {
                        log_error("seq-start larger than seq-end, ignoring\n");
                        start = 0;
                        end = 0;
                }

                if (start > kernel_seq || end > kernel_seq) {
                        log_error("seq-start or seq-end larger than current kernel value, ignoring\n");
                        start = 0;
                        end = 0;
                }
                log_debug("start=%llu end=%llu current=%llu\n", (unsigned long long)start, (unsigned long long)end, kernel_seq);
        } else {
                if (end > 0) {
                        log_error("seq-end needs seq-start parameter, ignoring\n");
                        end = 0;
                }
        }

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                struct udev_ctrl *uctrl;

                uctrl = udev_ctrl_new(udev);
                if (uctrl != NULL) {
                        if (udev_ctrl_send_ping(uctrl, timeout) < 0) {
                                log_debug("no connection to daemon\n");
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
                log_error("inotify_init failed: %m\n");
        } else {
                if (inotify_add_watch(pfd[0].fd, "/run/udev" , IN_MOVED_TO) < 0) {
                        log_error("watching /run/udev failed\n");
                        close(pfd[0].fd);
                        pfd[0].fd = -1;
                }
        }

        for (;;) {
                struct stat statbuf;

                if (exists != NULL && stat(exists, &statbuf) == 0) {
                        rc = EXIT_SUCCESS;
                        break;
                }

                if (start > 0) {
                        /* if asked for, wait for a specific sequence of events */
                        if (udev_queue_get_seqnum_sequence_is_finished(udev_queue, start, end) == 1) {
                                rc = EXIT_SUCCESS;
                                break;
                        }
                } else {
                        /* exit if queue is empty */
                        if (udev_queue_get_queue_is_empty(udev_queue)) {
                                rc = EXIT_SUCCESS;
                                break;
                        }
                }

                if (pfd[0].fd >= 0) {
                        int delay;

                        if (exists != NULL || start > 0)
                                delay = 100;
                        else
                                delay = 1000;
                        /* wake up after delay, or immediately after the queue is rebuilt */
                        if (poll(pfd, 1, delay) > 0 && pfd[0].revents & POLLIN) {
                                char buf[sizeof(struct inotify_event) + PATH_MAX];

                                read(pfd[0].fd, buf, sizeof(buf));
                        }
                } else {
                        sleep(1);
                }

                if (timeout > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - start_usec;
                        if (age_usec / (1000 * 1000) >= timeout) {
                                struct udev_list_entry *list_entry;

                                if (!quiet && udev_queue_get_queued_list_entry(udev_queue) != NULL) {
                                        log_debug("timeout waiting for udev queue\n");
                                        printf("\nudevadm settle - timeout of %i seconds reached, the event queue contains:\n", timeout);
                                        udev_list_entry_foreach(list_entry, udev_queue_get_queued_list_entry(udev_queue))
                                                printf("  %s (%s)\n",
                                                udev_list_entry_get_name(list_entry),
                                                udev_list_entry_get_value(list_entry));
                                }

                                break;
                        }
                }
        }
out:
        if (pfd[0].fd >= 0)
                close(pfd[0].fd);
        udev_queue_unref(udev_queue);
        return rc;
}

const struct udevadm_cmd udevadm_settle = {
        .name = "settle",
        .cmd = adm_settle,
        .help = "wait for the event queue to finish",
};
