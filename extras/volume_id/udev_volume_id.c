/*
 * udev_volume_id - udev callout to read filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	sample udev rule for creation of a symlink with the filsystem uuid:
 *	KERNEL="sd*", PROGRAM="/sbin/udev_volume_id -M%M -m%m -u", SYMLINK="%c"
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "volume_id.h"

int main(int argc, char *argv[])
{
	struct volume_id *vid;
	const char help[] = "usage: udev_volume_id -m<minor> -M<major> [-t|-l|-u]\n";
	int major = -1;
	int minor = -1;
	char *tail;
	static const char short_options[] = "M:m:htlu";
	int option;
	char print = '\0';
	int rc;


	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		switch (option) {
		case 'M':
			major = (int) strtoul(optarg, &tail, 10);
			if (tail[0] != '\0') {
				printf("invalid major\n");
				exit(1);
			}
			break;
		case 'm':
			minor = (int) strtoul(optarg, &tail, 10);
			if (tail[0] != '\0') {
				printf("invalid minor\n");
				exit(1);
			}
			break;
		case 't':
			print = 't';
			break;
		case 'l':
			print = 'l';
			break;
		case 'u':
			print = 'u';
			break;
		case 'h':
		case '?':
		default:
			printf(help);
			exit(1);
		}
	}

	if (major == -1 || minor == -1) {
		printf(help);
		exit(1);
	}

	vid = volume_id_open_dev_t(makedev(major, minor));
	if (vid == NULL) {
		printf("error open volume\n");
		exit(1);
	}

	rc = volume_id_probe(vid, ALL);
	if (rc != 0) {
		printf("error probing volume\n");
		exit(1);
	}

	switch (print) {
	case 't':
		printf("%s\n", vid->fs_name);
		break;
	case 'l':
		if (vid->label_string[0] == '\0')
			exit(2);
		printf("%s\n", vid->label_string);
		break;
	case 'u':
		if (vid->uuid_string[0] == '\0')
			exit(2);
		printf("%s\n", vid->uuid_string);
		break;
	default:
		printf("T:%s\n", vid->fs_name);
		printf("L:%s\n", vid->label_string);
		printf("U:%s\n", vid->uuid_string);
	}

	volume_id_close(vid);

	exit(0);
}
