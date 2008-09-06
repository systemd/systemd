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


struct udevice *udev_device_init(struct udev *udev)
{
	struct udevice *udevice;

	udevice = malloc(sizeof(struct udevice));
	if (udevice == NULL)
		return NULL;
	memset(udevice, 0x00, sizeof(struct udevice));

	udevice->udev = udev;

	INIT_LIST_HEAD(&udevice->symlink_list);
	INIT_LIST_HEAD(&udevice->run_list);
	INIT_LIST_HEAD(&udevice->env_list);

	/* set sysfs device to local storage, can be overridden if needed */
	udevice->dev = &udevice->dev_local;

	/* default node permissions */
	udevice->mode = 0660;
	strcpy(udevice->owner, "root");
	strcpy(udevice->group, "root");

	udevice->event_timeout = -1;
	return udevice;
}

void udev_device_cleanup(struct udevice *udevice)
{
	if (udevice == NULL)
		return;
	name_list_cleanup(udevice->udev, &udevice->symlink_list);
	name_list_cleanup(udevice->udev, &udevice->run_list);
	name_list_cleanup(udevice->udev, &udevice->env_list);
	free(udevice);
}

dev_t udev_device_get_devt(struct udevice *udevice)
{
	const char *attr;
	unsigned int maj, min;

	/* read it from sysfs  */
	attr = sysfs_attr_get_value(udevice->udev, udevice->dev->devpath, "dev");
	if (attr != NULL) {
		if (sscanf(attr, "%u:%u", &maj, &min) == 2)
			return makedev(maj, min);
	}
	return makedev(0, 0);
}
