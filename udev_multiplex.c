/*
 * udev_multiplex.c directory multiplexer
 * 
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

/*
 * This essentially emulates the following shell script logic in C:
 *	DIR="/etc/dev.d"
 *	export DEVNAME="whatever_dev_name_udev_just_gave"
 *	for I in "${DIR}/$DEVNAME/"*.dev "${DIR}/$1/"*.dev "${DIR}/default/"*.dev ; do
 *		if [ -f $I ]; then $I $1 ; fi
 *	done
 *	exit 1;
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "udev.h"
#include "udev_libc_wrapper.h"
#include "udev_utils.h"
#include "logging.h"


/* 
 * runs files in these directories in order:
 * 	<node name given by udev>/
 * 	subsystem/
 * 	default/
 */
void udev_multiplex_directory(struct udevice *udev, const char *basedir, const char *suffix)
{
	char dirname[PATH_SIZE];
	struct name_entry *name_loop, *name_tmp;
	LIST_HEAD(name_list);

	/* chop the device name up into pieces based on '/' */
	if (udev->name[0] != '\0') {
		char devname[PATH_SIZE];
		char *temp;

		strlcpy(devname, udev->name, sizeof(devname));
		temp = strchr(devname, '/');
		while (temp != NULL) {
			temp[0] = '\0';

			/* don't call the subsystem directory here */
			if (strcmp(devname, udev->subsystem) != 0) {
				snprintf(dirname, sizeof(dirname), "%s/%s", basedir, devname);
				dirname[sizeof(dirname)-1] = '\0';
				add_matching_files(&name_list, dirname, suffix);
			}

			temp[0] = '/';
			++temp;
			temp = strchr(temp, '/');
		}
	}

	if (udev->name[0] != '\0') {
		snprintf(dirname, sizeof(dirname), "%s/%s", basedir, udev->name);
		dirname[sizeof(dirname)-1] = '\0';
		add_matching_files(&name_list, dirname, suffix);
	}

	if (udev->subsystem[0] != '\0') {
		snprintf(dirname, sizeof(dirname), "%s/%s", basedir, udev->subsystem);
		dirname[sizeof(dirname)-1] = '\0';
		add_matching_files(&name_list, dirname, suffix);
	}

	snprintf(dirname, sizeof(dirname), "%s/default", basedir);
	dirname[sizeof(dirname)-1] = '\0';
	add_matching_files(&name_list, dirname, suffix);

	list_for_each_entry_safe(name_loop, name_tmp, &name_list, node) {
		execute_command(name_loop->name, udev->subsystem);
		list_del(&name_loop->node);
	}

}
