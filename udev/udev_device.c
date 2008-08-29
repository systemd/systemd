/*
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "udev.h"
#include "udev_rules.h"


struct udevice *udev_device_init(struct udevice *udev)
{
	if (udev == NULL)
		udev = malloc(sizeof(struct udevice));
	if (udev == NULL)
		return NULL;
	memset(udev, 0x00, sizeof(struct udevice));

	INIT_LIST_HEAD(&udev->symlink_list);
	INIT_LIST_HEAD(&udev->run_list);
	INIT_LIST_HEAD(&udev->env_list);

	/* set sysfs device to local storage, can be overridden if needed */
	udev->dev = &udev->dev_local;

	/* default node permissions */
	udev->mode = 0660;
	strcpy(udev->owner, "root");
	strcpy(udev->group, "root");

	udev->event_timeout = -1;

	return udev;
}

void udev_device_cleanup(struct udevice *udev)
{
	name_list_cleanup(&udev->symlink_list);
	name_list_cleanup(&udev->run_list);
	name_list_cleanup(&udev->env_list);
	free(udev);
}

dev_t udev_device_get_devt(struct udevice *udev)
{
	const char *attr;
	unsigned int maj, min;

	/* read it from sysfs  */
	attr = sysfs_attr_get_value(udev->dev->devpath, "dev");
	if (attr != NULL) {
		if (sscanf(attr, "%u:%u", &maj, &min) == 2)
			return makedev(maj, min);
	}
	return makedev(0, 0);
}
