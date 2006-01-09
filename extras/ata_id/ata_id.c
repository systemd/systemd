/*
 * ata_id - reads product/serial number from ATA drives
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hdreg.h>

#include "../../udev.h"

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

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
	struct hd_driveid id;
	char model[41];
	char serial[21];
	char revision[9];
	const char *node = NULL;
	int i;
	int export = 0;
	int fd;
	int rc = 0;

	logging_init("ata_id");

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--export") == 0) {
			export = 1;
		} else
			node = arg;
	}
	if (!node) {
		err("no node specified");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		err("unable to open '%s'", node);
		rc = 1;
		goto exit;
	}

	if (ioctl(fd, HDIO_GET_IDENTITY, &id)) {
		err("HDIO_GET_IDENTITY failed for '%s'", node);
		rc = 3;
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
	logging_close();
	return rc;
}
