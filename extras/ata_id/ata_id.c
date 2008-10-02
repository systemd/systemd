/*
 * ata_id - reads product/serial number from ATA drives
 *
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hdreg.h>

#include "../../udev/udev.h"

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	vsyslog(priority, format, args);
}

static void set_str(char *to, const char *from, size_t count)
{
	size_t i, j, len;

	/* strip trailing whitespace */
	len = strnlen(from, count);
	while (len && isspace(from[len-1]))
		len--;

	/* strip leading whitespace */
	i = 0;
	while (isspace(from[i]) && (i < len))
		i++;

	j = 0;
	while (i < len) {
		/* substitute multiple whitespace */
		if (isspace(from[i])) {
			while (isspace(from[i]))
				i++;
			to[j++] = '_';
		}
		/* skip chars */
		if (from[i] == '/') {
			i++;
			continue;
		}
		to[j++] = from[i++];
	}
	to[j] = '\0';
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	struct hd_driveid id;
	char model[41];
	char serial[21];
	char revision[9];
	const char *node = NULL;
	int export = 0;
	int fd;
	int rc = 0;
	static const struct option options[] = {
		{ "export", no_argument, NULL, 'x' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	logging_init("ata_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "xh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'x':
			export = 1;
			break;
		case 'h':
			printf("Usage: ata_id [--export] [--help] <device>\n"
			       "  --export    print values as environemt keys\n"
			       "  --help      print this help text\n\n");
		default:
			rc = 1;
			goto exit;
		}
	}

	node = argv[optind];
	if (node == NULL) {
		err(udev, "no node specified\n");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		err(udev, "unable to open '%s'\n", node);
		rc = 1;
		goto exit;
	}

	if (ioctl(fd, HDIO_GET_IDENTITY, &id)) {
		if (errno == ENOTTY) {
			info(udev, "HDIO_GET_IDENTITY unsupported for '%s'\n", node);
			rc = 2;
		} else {
			err(udev, "HDIO_GET_IDENTITY failed for '%s'\n", node);
			rc = 3;
		}
		goto close;
	}

	set_str(model, (char *) id.model, 40);
	set_str(serial, (char *) id.serial_no, 20);
	set_str(revision, (char *) id.fw_rev, 8);

	if (export) {
		if ((id.config >> 8) & 0x80) {
			/* This is an ATAPI device */
			switch ((id.config >> 8) & 0x1f) {
			case 0:
				printf("ID_TYPE=cd\n");
				break;
			case 1:
				printf("ID_TYPE=tape\n");
				break;
			case 5:
				printf("ID_TYPE=cd\n");
				break;
			case 7:
				printf("ID_TYPE=optical\n");
				break;
			default:
				printf("ID_TYPE=generic\n");
				break;
			}
		} else {
			printf("ID_TYPE=disk\n");
		}
		printf("ID_MODEL=%s\n", model);
		printf("ID_SERIAL=%s\n", serial);
		printf("ID_REVISION=%s\n", revision);
		printf("ID_BUS=ata\n");
	} else {
		if (serial[0] != '\0')
			printf("%s_%s\n", model, serial);
		else
			printf("%s\n", model);
	}

close:
	close(fd);
exit:
	udev_unref(udev);
	logging_close();
	return rc;
}
