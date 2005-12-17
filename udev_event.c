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
#include <sys/stat.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_utils.h"
#include "list.h"


dev_t get_devt(struct sysfs_class_device *class_dev)
{
	struct sysfs_attribute *attr = NULL;
	unsigned int major, minor;
	char *maj, *min;

	maj = getenv("MAJOR");
	min = getenv("MINOR");

	if (maj && min) {
		major = atoi(maj);
		minor = atoi(min);
	} else {
		attr = sysfs_get_classdev_attr(class_dev, "dev");
		if (attr == NULL)
			return 0;
		dbg("dev='%s'", attr->value);

		if (sscanf(attr->value, "%u:%u", &major, &minor) != 2)
			return 0;
	}

	dbg("found major=%d, minor=%d", major, minor);
	return makedev(major, minor);
}

int udev_process_event(struct udev_rules *rules, struct udevice *udev)
{
	int retval;
	char path[PATH_SIZE];

	if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS || udev->type == DEV_NET) {
		/* handle device node */
		if (strcmp(udev->action, "add") == 0) {
			struct sysfs_class_device *class_dev;

			dbg("node add");
			snprintf(path, sizeof(path), "%s%s", sysfs_path, udev->devpath);
			path[sizeof(path)-1] = '\0';
			class_dev = sysfs_open_class_device_path(path);
			if (class_dev == NULL) {
				dbg("open class device failed");
				return 0;
			}
			dbg("opened class_dev->name='%s'", class_dev->name);

			/* get major/minor */
			if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS)
				udev->devt = get_devt(class_dev);

			if (udev->type == DEV_NET || udev->devt) {
				/* name device */
				udev_rules_get_name(rules, udev, class_dev);
				if (udev->ignore_device) {
					info("device event will be ignored");
					sysfs_close_class_device(class_dev);
					return 0;
				}
				if (udev->name[0] != '\0') {
					/* create node, store in db */
					retval = udev_add_device(udev, class_dev);
				} else {
					info("device node creation supressed");
				}
			} else {
				dbg("no dev-file found");
				udev_rules_get_run(rules, udev, class_dev, NULL);
				if (udev->ignore_device) {
					info("device event will be ignored");
					sysfs_close_class_device(class_dev);
					return 0;
				}
			}
			sysfs_close_class_device(class_dev);
		} else if (strcmp(udev->action, "remove") == 0) {
			struct name_entry *name_loop;

			/* get data from db, remove db-entry, delete node */
			dbg("node remove");
			retval = udev_remove_device(udev);

			/* restore stored persistent data */
			list_for_each_entry(name_loop, &udev->env_list, node)
				putenv(name_loop->name);

			udev_rules_get_run(rules, udev, NULL, NULL);
			if (udev->ignore_device) {
				dbg("device event will be ignored");
				return 0;
			}
		}
	} else if (udev->type == DEV_DEVICE && strcmp(udev->action, "add") == 0) {
		struct sysfs_device *devices_dev;

		dbg("devices add");
		snprintf(path, sizeof(path), "%s%s", sysfs_path, udev->devpath);
		path[sizeof(path)-1] = '\0';
		devices_dev = sysfs_open_device_path(path);
		if (!devices_dev) {
			dbg("devices device unavailable (probably remove has beaten us)");
			return 0;
		}

		dbg("devices device opened '%s'", path);
		udev_rules_get_run(rules, udev, NULL, devices_dev);
		sysfs_close_device(devices_dev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return 0;
		}
	} else {
		dbg("default handling");
		udev_rules_get_run(rules, udev, NULL, NULL);
		if (udev->ignore_device) {
			info("device event will be ignored");
			return 0;
		}
	}
	return 0;
}
