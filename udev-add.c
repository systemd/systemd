/*
 * udev-add.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 *
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
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

static char sysfs_path[SYSFS_PATH_MAX];

/* 
 * Right now the major/minor of a device is stored in a file called
 * "dev" in sysfs.
 * The number is stored as:
 * 	MM:mm
 * 		MM is the major
 * 		mm is the minor
 * 		The value is in decimal.
 */
static int get_major_minor(struct sysfs_class_device *class_dev, int *major, int *minor)
{
	int retval = -ENODEV;

	char *dev;

	dev = sysfs_get_value_from_attributes(class_dev->directory->attributes, "dev");
	if (dev == NULL)
		goto exit;

	dbg("dev = %s", dev);

	if (sscanf(dev, "%u:%u", major, minor) != 2)
		goto exit;

	dbg("found major = %d, minor = %d", *major, *minor);

	retval = 0;
exit:
	return retval;
}

/*
 * We also want to add some permissions here, and possibly some symlinks
 */
static int create_node(char *name, char type, int major, int minor, mode_t mode)
{
	char filename[255];
	int retval = 0;
	strncpy(filename, UDEV_ROOT, sizeof(filename));
	strncat(filename, name, sizeof(filename));
	switch (type) {
	case 'b':
		mode |= S_IFBLK;
		break;
	case 'c':
	case 'u':
		mode |= S_IFCHR;
		break;
	case 'p':
		mode |= S_IFIFO;
		break;
	default:
		dbg("unknown node type %c\n", type);
		return -EINVAL;
	}

	dbg("mknod(%s, %#o, %u, %u)", filename, mode, major, minor);
	retval = mknod(filename, mode, makedev(major, minor));
	if (retval)
		dbg("mknod(%s, %#o, %u, %u) failed with error '%s'",
		    filename, mode, major, minor, strerror(errno));
	return retval;
}

static struct sysfs_class_device *get_class_dev(char *device_name)
{
	char dev_path[SYSFS_PATH_MAX];
	struct sysfs_class_device *class_dev = NULL;

	strcpy(dev_path, sysfs_path);
	strcat(dev_path, device_name);

	dbg("looking at %s", dev_path);

	/* open up the sysfs class device for this thing... */
	class_dev = sysfs_open_class_device(dev_path);
	if (class_dev == NULL) {
		dbg ("sysfs_open_class_device failed");
		goto exit;
	}
	dbg("class_dev->name = %s", class_dev->name);

exit:
	return class_dev;
}

/* wait for the "dev" file to show up in the directory in sysfs.
 * If it doesn't happen in about 10 seconds, give up.
 */
#define SECONDS_TO_WAIT_FOR_DEV		10
int sleep_for_dev(char *device)
{
	char filename[SYSFS_PATH_MAX + 6];
	struct stat buf;
	int loop = 0;
	int retval = -ENODEV;

	strcpy(filename, sysfs_path);
	strcat(filename, device);
	strcat(filename, "/dev");

	while (loop < SECONDS_TO_WAIT_FOR_DEV) {
		dbg("looking for %s", filename);
		retval = stat(filename, &buf);
		if (retval == 0) {
			retval = 0;
			goto exit;
		}

		/* sleep for a second or two to give the kernel a chance to
		 * create the dev file */
		sleep(1);
	}
	retval = -ENODEV;
exit:
	return retval;
}

int udev_add_device(char *device, char *subsystem)
{
	struct sysfs_class_device *class_dev;
	struct device_attr attr;
	int major;
	int minor;
	char type;
	int retval = -EINVAL;

	/* for now, the block layer is the only place where block devices are */
	if (strcmp(subsystem, "block") == 0)
		type = 'b';
	else
		type = 'c';

	retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
	dbg("sysfs_path = %s", sysfs_path);
	if (retval) {
		dbg("sysfs_get_mnt_path failed");
		goto exit;
	}

	retval = sleep_for_dev(device);
	if (retval)
		goto exit;

	class_dev = get_class_dev(device);
	if (class_dev == NULL)
		goto exit;

	retval = namedev_name_device(class_dev, &attr);
	if (retval)
		return retval;

	retval = get_major_minor(class_dev, &major, &minor);
	if (retval) {
		dbg("get_major_minor failed");
		goto exit;
	}

	retval = udevdb_add_device(device, class_dev, attr.name, type, major, minor, attr.mode);

	if (retval != 0)
		dbg("udevdb_add_device failed, but we are going to try to create the node anyway. "
		    "But remove might not work properly for this device.");

	sysfs_close_class_device(class_dev);

	return create_node(attr.name, type, major, minor, attr.mode);

exit:
	return retval;
}

