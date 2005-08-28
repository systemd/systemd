/*
 * udev_utils.c - generic stuff used by udev
 *
 * Copyright (C) 2004, 2005 Kay Sievers <kay.sievers@vrfy.org>
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


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "list.h"


int udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem, const char *action)
{
	char *pos;

	memset(udev, 0x00, sizeof(struct udevice));
	INIT_LIST_HEAD(&udev->symlink_list);
	INIT_LIST_HEAD(&udev->run_list);
	INIT_LIST_HEAD(&udev->env_list);

	if (subsystem)
		strlcpy(udev->subsystem, subsystem, sizeof(udev->subsystem));

	if (action)
		strlcpy(udev->action, action, sizeof(udev->action));

	if (devpath) {
		strlcpy(udev->devpath, devpath, sizeof(udev->devpath));
		remove_trailing_chars(udev->devpath, '/');

		if (strncmp(udev->devpath, "/block/", 7) == 0)
			udev->type = DEV_BLOCK;
		else if (strncmp(udev->devpath, "/class/net/", 11) == 0)
			udev->type = DEV_NET;
		else if (strncmp(udev->devpath, "/class/", 7) == 0)
			udev->type = DEV_CLASS;
		else if (strncmp(udev->devpath, "/devices/", 9) == 0)
			udev->type = DEV_DEVICE;

		/* get kernel name */
		pos = strrchr(udev->devpath, '/');
		if (pos) {
			strlcpy(udev->kernel_name, &pos[1], sizeof(udev->kernel_name));
			dbg("kernel_name='%s'", udev->kernel_name);

			/* Some block devices have '!' in their name, change that to '/' */
			pos = udev->kernel_name;
			while (pos[0] != '\0') {
				if (pos[0] == '!')
					pos[0] = '/';
				pos++;
			}

			/* get kernel number */
			pos = &udev->kernel_name[strlen(udev->kernel_name)];
			while (isdigit(pos[-1]))
				pos--;
			strlcpy(udev->kernel_number, pos, sizeof(udev->kernel_number));
			dbg("kernel_number='%s'", udev->kernel_number);
		}
	}

	if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS) {
		udev->mode = 0660;
		strcpy(udev->owner, "root");
		strcpy(udev->group, "root");
	}

	return 0;
}

void udev_cleanup_device(struct udevice *udev)
{
	name_list_cleanup(&udev->symlink_list);
	name_list_cleanup(&udev->run_list);
	name_list_cleanup(&udev->env_list);
}
