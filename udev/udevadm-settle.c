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
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

#define DEFAULT_TIMEOUT			180
#define LOOP_PER_SECOND			20

static volatile sig_atomic_t is_timeout;

static void sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			is_timeout = 1;
		case SIGUSR1:
			;
	}
}

int udevadm_settle(struct udev *udev, int argc, char *argv[])
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
	unsigned long long start = 0;
	unsigned long long end = 0;
	int quiet = 0;
	const char *exists = NULL;
	int timeout = DEFAULT_TIMEOUT;
	struct sigaction act;
	struct udev_queue *udev_queue = NULL;
	int rc = 1;

	dbg(udev, "version %s\n", VERSION);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);

	while (1) {
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
			dbg(udev, "timeout=%i\n", timeout);
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
			exit(0);
		}
	}

	if (timeout > 0)
		alarm(timeout);
	else
		is_timeout = 1;

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
			err(udev, "seq-start larger than seq-end, ignoring\n");
			start = 0;
			end = 0;
		}

		if (start > kernel_seq || end > kernel_seq) {
			err(udev, "seq-start or seq-end larger than current kernel value, ignoring\n");
			start = 0;
			end = 0;
		}
		info(udev, "start=%llu end=%llu current=%llu\n", start, end, kernel_seq);
	} else {
		if (end > 0) {
			err(udev, "seq-end needs seq-start parameter, ignoring\n");
			end = 0;
		}
	}

	/* guarantee that the udev daemon isn't pre-processing */
	if (getuid() == 0) {
		struct udev_ctrl *uctrl;

		uctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
		if (uctrl != NULL) {
			sigset_t mask, oldmask;

			sigemptyset(&mask);
			sigaddset(&mask, SIGUSR1);
			sigaddset(&mask, SIGALRM);
			sigprocmask(SIG_BLOCK, &mask, &oldmask);
			if (udev_ctrl_send_settle(uctrl) > 0)
				sigsuspend(&oldmask);
			sigprocmask(SIG_SETMASK, &oldmask, NULL);
			udev_ctrl_unref(uctrl);
		}
	}

	while (1) {
		struct stat statbuf;
		const struct timespec duration = { 0 , 1000 * 1000 * 1000 / LOOP_PER_SECOND };

		if (exists != NULL && stat(exists, &statbuf) == 0) {
			rc = 0;
			break;
		}

		if (start > 0) {
			/* if asked for, wait for a specific sequence of events */
			if (udev_queue_get_seqnum_sequence_is_finished(udev_queue, start, end) == 1) {
				rc = 0;
				break;
			}
		} else {
			/* exit if queue is empty */
			if (udev_queue_get_queue_is_empty(udev_queue)) {
				rc = 0;
				break;
			}
		}

		if (is_timeout)
			break;

		nanosleep(&duration, NULL);
	}

	/* if we reached the timeout, print the list of remaining events */
	if (is_timeout) {
		struct udev_list_entry *list_entry;

		if (!quiet && udev_queue_get_queued_list_entry(udev_queue) != NULL) {
			info(udev, "timeout waiting for udev queue\n");
			printf("\nudevadm settle - timeout of %i seconds reached, the event queue contains:\n", timeout);
			udev_list_entry_foreach(list_entry, udev_queue_get_queued_list_entry(udev_queue))
				printf("  %s (%s)\n",
				       udev_list_entry_get_name(list_entry),
				       udev_list_entry_get_value(list_entry));
		}
	}

	udev_queue_unref(udev_queue);
	return rc;
}
