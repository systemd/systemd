/*
 * udev_volume_id - udev callout to read filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	sample udev rule for creation of a symlink with the filsystem uuid:
 *	KERNEL="sd*", PROGRAM="/sbin/udev_volume_id -u %N", SYMLINK="%c"
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>

#include "../../udev_utils.h"
#include "../../logging.h"
#include "volume_id/volume_id.h"
#include "volume_id/dasd.h"

#define BLKGETSIZE64 _IOR(0x12,114,size_t)

#ifdef USE_LOG
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

extern int optind;

int main(int argc, char *argv[])
{
	const char help[] = "usage: udev_volume_id [-t|-l|-u] <device>\n"
			    "       -t filesystem type\n"
			    "       -l filesystem label\n"
			    "       -u filesystem uuid\n"
			    "\n";
	static const char short_options[] = "htlu";
	struct volume_id *vid = NULL;
	const char *device;
	char print = 'a';
	static char name[VOLUME_ID_LABEL_SIZE];
	int len, i, j;
	unsigned long long size;
	int rc = 1;

	logging_init("udev_volume_id");

	while (1) {
		int option;

		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		switch (option) {
		case 't':
			print = 't';
			continue;
		case 'l':
			print = 'l';
			continue;
		case 'u':
			print = 'u';
			continue;
		case 'h':
		case '?':
		default:
			printf(help);
			exit(1);
		}
	}

	device = argv[optind];
	if (device == NULL) {
		printf(help);
		exit(1);
	}

	vid = volume_id_open_node(device);
	if (vid == NULL) {
		printf("error open volume\n");
		goto exit;
	}

	if (ioctl(vid->fd, BLKGETSIZE64, &size) != 0)
		size = 0;

	if (volume_id_probe_all(vid, 0, size) == 0)
		goto print;

	if (volume_id_probe_dasd(vid) == 0)
		goto print;

	printf("unknown volume type\n");
	goto exit;


print:
	len = strnlen(vid->label, VOLUME_ID_LABEL_SIZE);

	/* remove trailing spaces */
	while (len > 0 && isspace(vid->label[len-1]))
		len--;
	name[len] = '\0';

	/* substitute chars */
	i = 0;
	j = 0;
	while (j < len) {
		switch(vid->label[j]) {
		case '/' :
			break;
		case ' ' :
			name[i++] = '_';
			break;
		default :
			name[i++] = vid->label[j];
		}
		j++;
	}
	name[i] = '\0';

	switch (print) {
	case 't':
		printf("%s\n", vid->type);
		break;
	case 'l':
		if (name[0] == '\0' ||
		    (vid->usage_id != VOLUME_ID_FILESYSTEM && vid->usage_id != VOLUME_ID_DISKLABEL)) {
			rc = 2;
			goto exit;
		}
		printf("%s\n", name);
		break;
	case 'u':
		if (vid->uuid[0] == '\0' || vid->usage_id != VOLUME_ID_FILESYSTEM) {
			rc = 2;
			goto exit;
		}
		printf("%s\n", vid->uuid);
		break;
	case 'a':
		printf("F:%s\n", vid->usage);
		printf("T:%s\n", vid->type);
		printf("V:%s\n", vid->type_version);
		printf("L:%s\n", vid->label);
		printf("N:%s\n", name);
		printf("U:%s\n", vid->uuid);
	}
	rc = 0;

exit:
	if (vid != NULL)
		volume_id_close(vid);

	logging_close();

	exit(rc);
}
