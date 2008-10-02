/*
 * Copyright (C) 2006-2008 Kay Sievers <kay@vrfy.org>
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
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

#define DEFAULT_TIMEOUT			180
#define LOOP_PER_SECOND			20

int udevadm_settle(struct udev *udev, int argc, char *argv[])
{
	static const struct option options[] = {
		{ "timeout", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int timeout = DEFAULT_TIMEOUT;
	struct udev_queue *udev_queue;
	int loop;
	int rc = 0;

	dbg(udev, "version %s\n", VERSION);

	while (1) {
		int option;
		int seconds;

		option = getopt_long(argc, argv, "t:h", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 't':
			seconds = atoi(optarg);
			if (seconds > 0)
				timeout = seconds;
			else
				fprintf(stderr, "invalid timeout value\n");
			dbg(udev, "timeout=%i\n", timeout);
			break;
		case 'h':
			printf("Usage: udevadm settle [--help] [--timeout=<seconds>]\n\n");
			goto exit;
		}
	}

	udev_queue = udev_queue_new(udev);
	if (udev_queue == NULL)
		goto exit;
	loop = timeout * LOOP_PER_SECOND;
	while (loop--) {
		if (udev_queue_get_queue_is_empty(udev_queue))
			break;
		usleep(1000 * 1000 / LOOP_PER_SECOND);
	}
	if (loop <= 0) {
		struct udev_list_entry *list_entry;

		info(udev, "timeout waiting for udev queue\n");
		printf("\ndevadm settle timeout of %i seconds reached, the event queue contains:\n", timeout);
		udev_list_entry_foreach(list_entry, udev_queue_get_queued_list_entry(udev_queue))
			printf("  '%s' [%s]\n",
			       udev_list_entry_get_name(list_entry),
			       udev_list_entry_get_value(list_entry));
		rc = 1;
	}
exit:
	udev_queue_unref(udev_queue);
	return rc;
}
