/*
 * udev_event.c - udev event process
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

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "list.h"


int udev_process_event(struct udev_rules *rules, struct udevice *udev)
{
	int retval;
	char path[PATH_SIZE];
	const char *error;

	if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS || udev->type == DEV_NET) {
		/* handle device node */
		if (strcmp(udev->action, "add") == 0) {
			struct sysfs_class_device *class_dev;

			/* wait for sysfs of /sys/class /sys/block */
			dbg("node add");
			snprintf(path, sizeof(path), "%s%s", sysfs_path, udev->devpath);
			path[sizeof(path)-1] = '\0';
			class_dev = wait_class_device_open(path);
			if (class_dev == NULL) {
				dbg("open class device failed");
				return 0;
			}
			dbg("opened class_dev->name='%s'", class_dev->name);
			wait_for_class_device(class_dev, &error);

			/* get major/minor */
			if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS)
				udev->devt = get_devt(class_dev);

			if (udev->type == DEV_NET || udev->devt) {
				/* name device */
				udev_rules_get_name(rules, udev, class_dev);
				if (udev->ignore_device) {
					info("device event will be ignored");
					sysfs_close_class_device(class_dev);
					return -1;
				}
				if (udev->name[0] == '\0') {
					info("device node creation supressed");
					sysfs_close_class_device(class_dev);
					return -1;
				}
				/* create node, store in db */
				retval = udev_add_device(udev, class_dev);
			} else {
				dbg("no dev-file found");
				udev_rules_get_run(rules, udev, class_dev, NULL);
				if (udev->ignore_device) {
					info("device event will be ignored");
					sysfs_close_class_device(class_dev);
					return -1;
				}
			}
			sysfs_close_class_device(class_dev);
		} else if (strcmp(udev->action, "remove") == 0) {
			dbg("node remove");
			udev_rules_get_run(rules, udev, NULL, NULL);
			if (udev->ignore_device) {
				dbg("device event will be ignored");
				return -1;
			}

			/* get name from db, remove db-entry, delete node */
			retval = udev_remove_device(udev);
		}

		/* export name of device node or netif */
		if (udev->devname[0] != '\0')
			setenv("DEVNAME", udev->devname, 1);
	} else if (udev->type == DEV_DEVICE && strcmp(udev->action, "add") == 0) {
		struct sysfs_device *devices_dev;

		/* wait for sysfs of /sys/devices/ */
		dbg("devices add");
		snprintf(path, sizeof(path), "%s%s", sysfs_path, udev->devpath);
		path[sizeof(path)-1] = '\0';
		devices_dev = wait_devices_device_open(path);
		if (!devices_dev) {
			dbg("devices device unavailable (probably remove has beaten us)");
			return 0;
		}
		dbg("devices device opened '%s'", path);
		wait_for_devices_device(devices_dev, &error);
		udev_rules_get_run(rules, udev, NULL, devices_dev);
		sysfs_close_device(devices_dev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return -1;
		}
	} else {
		dbg("default handling");
		udev_rules_get_run(rules, udev, NULL, NULL);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return -1;
		}
	}
	return 0;
}
