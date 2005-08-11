/*
 * cdrom_id - determines the capabilities of cdrom drives
 *
 * Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 *
 * Framework based on ata_id which is:
 *	Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/cdrom.h>

#include "../../logging.h"
#include "../../udev_utils.h"

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

int main(int argc, char *argv[])
{
	const char *node = NULL;
	int i;
	int export = 0;
	int fd;
	int rc = 0;
	int result;

	logging_init("cdrom_id");

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

	fd = open(node, O_RDONLY);
	if (fd < 0)
		if (errno == ENOMEDIUM)
			fd = open(node, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		err("unable to open '%s'", node);
		rc = 1;
		goto exit;
	}

	result = ioctl(fd, CDROM_GET_CAPABILITY, NULL);
	if (result < 0) {
		err("CDROM_GET_CABILITY failed for '%s'", node);
		rc = 3;
		goto close;
	}

	printf("ID_CDROM=1\n");

	if (result & CDC_CD_R)
		printf("ID_CDROM_CD_R=1\n");
	if (result & CDC_CD_RW)
		printf("ID_CDROM_CD_RW=1\n");

	if (result & CDC_DVD)
		printf("ID_CDROM_DVD=1\n");
	if (result & CDC_DVD_R)
		printf("ID_CDROM_DVD_R=1\n");
	if (result & CDC_DVD_RAM)
		printf("ID_CDROM_DVD_RAM=1\n");

	if (result & CDC_MRW)
		printf("ID_CDROM_MRW=1\n");
	if (result & CDC_MRW_W)
		printf("ID_CDROM_MRW_W=1\n");

	if (result & CDC_RAM)
		printf("ID_CDROM_RAM=1\n");
	goto close;

close:
	close(fd);
exit:
	logging_close();
	return rc;
}
