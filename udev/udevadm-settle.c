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

static void print_queue(struct udev *udev, const char *dir)
{
	LIST_HEAD(files);
	struct name_entry *item;

	if (add_matching_files(udev, &files, dir, NULL) < 0)
		return;

	printf("\n\nAfter the udevadm settle timeout, the events queue contains:\n\n");

	list_for_each_entry(item, &files, node) {
		char target[UTIL_NAME_SIZE];
		size_t len;
		const char *filename = strrchr(item->name, '/');

		if (filename == NULL)
			continue;
		filename++;
		if (*filename == '\0')
			continue;

		len = readlink(item->name, target, sizeof(target));
		if (len < 0)
			continue;
		target[len] = '\0';

		printf("%s: %s\n", filename, target);
	}

	printf("\n\n");
}

int udevadm_settle(struct udev *udev, int argc, char *argv[])
{
	char queuename[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE];
	unsigned long long seq_kernel;
	unsigned long long seq_udev;
	char seqnum[32];
	int fd;
	ssize_t len;
	int timeout = DEFAULT_TIMEOUT;
	int loop;
	static const struct option options[] = {
		{ "timeout", 1, NULL, 't' },
		{ "help", 0, NULL, 'h' },
		{}
	};
	int option;
	int rc = 1;
	int seconds;

	dbg(udev, "version %s\n", VERSION);

	while (1) {
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

	util_strlcpy(queuename, udev_get_dev_path(udev), sizeof(queuename));
	util_strlcat(queuename, "/.udev/queue", sizeof(queuename));

	loop = timeout * LOOP_PER_SECOND;
	while (loop--) {
		/* wait for events in queue to finish */
		while (loop--) {
			struct stat statbuf;

			if (stat(queuename, &statbuf) < 0) {
				info(udev, "queue is empty\n");
				break;
			}
			usleep(1000 * 1000 / LOOP_PER_SECOND);
		}
		if (loop <= 0) {
			info(udev, "timeout waiting for queue\n");
			print_queue(udev, queuename);
			goto exit;
		}

		/* read current udev seqnum */
		util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		util_strlcat(filename, "/.udev/uevent_seqnum", sizeof(filename));
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			goto exit;
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
		if (len <= 0)
			goto exit;
		seqnum[len] = '\0';
		seq_udev = strtoull(seqnum, NULL, 10);
		info(udev, "udev seqnum = %llu\n", seq_udev);

		/* read current kernel seqnum */
		util_strlcpy(filename, udev_get_sys_path(udev), sizeof(filename));
		util_strlcat(filename, "/kernel/uevent_seqnum", sizeof(filename));
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			goto exit;
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
		if (len <= 0)
			goto exit;
		seqnum[len] = '\0';
		seq_kernel = strtoull(seqnum, NULL, 10);
		info(udev, "kernel seqnum = %llu\n", seq_kernel);

		/* make sure all kernel events have arrived in the queue */
		if (seq_udev >= seq_kernel) {
			info(udev, "queue is empty and no pending events left\n");
			rc = 0;
			goto exit;
		}
		usleep(1000 * 1000 / LOOP_PER_SECOND);
		info(udev, "queue is empty, but events still pending\n");
	}

exit:
	return rc;
}
