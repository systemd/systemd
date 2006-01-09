/*
 * cdrom_id - determines the capabilities of cdrom drives
 *
 * Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>

#include "../../udev.h"

/*
 * Taken from the cdrom.h kernel include file.
 * Included here as some distros don't have an updated version
 * with all of the DVD flags.  So we just include our own, aren't
 * we so nice...
 */
#define CDROM_GET_CAPABILITY	0x5331	/* get capabilities */

/* capability flags used with the uniform CD-ROM driver */
#define CDC_CLOSE_TRAY		0x1	/* caddy systems _can't_ close */
#define CDC_OPEN_TRAY		0x2	/* but _can_ eject.  */
#define CDC_LOCK		0x4	/* disable manual eject */
#define CDC_SELECT_SPEED 	0x8	/* programmable speed */
#define CDC_SELECT_DISC		0x10	/* select disc from juke-box */
#define CDC_MULTI_SESSION 	0x20	/* read sessions>1 */
#define CDC_MCN			0x40	/* Medium Catalog Number */
#define CDC_MEDIA_CHANGED 	0x80	/* media changed */
#define CDC_PLAY_AUDIO		0x100	/* audio functions */
#define CDC_RESET		0x200	/* hard reset device */
#define CDC_IOCTLS		0x400	/* driver has non-standard ioctls */
#define CDC_DRIVE_STATUS	0x800	/* driver implements drive status */
#define CDC_GENERIC_PACKET	0x1000	/* driver implements generic packets */
#define CDC_CD_R		0x2000	/* drive is a CD-R */
#define CDC_CD_RW		0x4000	/* drive is a CD-RW */
#define CDC_DVD			0x8000	/* drive is a DVD */
#define CDC_DVD_R		0x10000	/* drive can write DVD-R */
#define CDC_DVD_RAM		0x20000	/* drive can write DVD-RAM */
#define CDC_MO_DRIVE		0x40000	/* drive is an MO device */
#define CDC_MRW			0x80000	/* drive can read MRW */
#define CDC_MRW_W		0x100000 /* drive can write MRW */
#define CDC_RAM			0x200000 /* ok to open for WRITE */

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
		info("no node specified");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		info("unable to open '%s'", node);
		rc = 1;
		goto exit;
	}

	result = ioctl(fd, CDROM_GET_CAPABILITY, NULL);
	if (result < 0) {
		info("CDROM_GET_CAPABILITY failed for '%s'", node);
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
close:
	close(fd);
exit:
	logging_close();
	return rc;
}
