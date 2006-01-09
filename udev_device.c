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

#include "udev.h"
#include "udev_rules.h"


struct udevice *udev_device_init(void)
{
	struct udevice *udev;

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
	unsigned int major, minor;

	/* read it from sysfs  */
	attr = sysfs_attr_get_value(udev->dev->devpath, "dev");
	if (attr != NULL) {
		if (sscanf(attr, "%u:%u", &major, &minor) == 2)
			return makedev(major, minor);
	}
	return makedev(0, 0);
}

int udev_device_event(struct udev_rules *rules, struct udevice *udev)
{
	int retval = 0;

	/* device node or netif */
	if ((major(udev->devt) != 0 || strcmp(udev->dev->subsystem, "net") == 0) &&
	    strcmp(udev->action, "add") == 0) {
		dbg("device node or netif add '%s'", udev->dev->devpath);
		udev_rules_get_name(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return 0;
		}
		/* create node, store in db */
		if (udev->name[0] != '\0')
			retval = udev_add_device(udev);
		else
			info("device node creation supressed");
		return 0;
	}

	if (major(udev->devt) != 0 && strcmp(udev->action, "remove") == 0) {
		struct name_entry *name_loop;

		udev_rules_get_run(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return 0;
		}
		/* get data from db, remove db-entry, delete node */
		retval = udev_remove_device(udev);

		/* restore stored persistent data */
		list_for_each_entry(name_loop, &udev->env_list, node)
			putenv(name_loop->name);
		return 0;
	}

	/* default devices */
	udev_rules_get_run(rules, udev);
	if (udev->ignore_device)
		info("device event will be ignored");

	return retval;
}
