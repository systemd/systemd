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
#include <sys/stat.h>

#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

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
 * we possibly want to add some symlinks here
 * only numeric owner/group id's are supported
 */
static int create_node(struct udevice *dev)
{
	char filename[255];
	int retval = 0;
	dev_t res;

	strncpy(filename, udev_root, sizeof(filename));
	strncat(filename, dev->name, sizeof(filename));

#ifdef __KLIBC__
	res = (dev->major << 8) | (dev->minor);
#else
	res = makedev(dev->major, dev->minor);
#endif

	switch (dev->type) {
	case 'b':
		dev->mode |= S_IFBLK;
		break;
	case 'c':
	case 'u':
		dev->mode |= S_IFCHR;
		break;
	case 'p':
		dev->mode |= S_IFIFO;
		break;
	default:
		dbg("unknown node type %c\n", dev->type);
		return -EINVAL;
	}

	dbg("mknod(%s, %#o, %u, %u)", filename, dev->mode, dev->major, dev->minor);
	retval = mknod(filename, dev->mode, res);
	if (retval)
		dbg("mknod(%s, %#o, %u, %u) failed with error '%s'",
		    filename, dev->mode, dev->major, dev->minor, strerror(errno));

	uid_t uid = 0;
	gid_t gid = 0;

	if (*dev->owner) {
		char *endptr;
		unsigned long id = strtoul(dev->owner, &endptr, 10);
		if (*endptr == 0x00)
			uid = (uid_t) id;
		else
			dbg("only numeric owner id supported: %s", dev->owner);
	}

	if (*dev->group) {
		char *endptr;
		unsigned long id = strtoul(dev->group, &endptr, 10);
		if (*endptr == 0x00)
			gid = (gid_t) id;
		else
			dbg("only numeric group id supported: %s", dev->group);
	}

	if (uid || gid) {
		dbg("chown(%s, %u, %u)", filename, uid, gid);
		retval = chown(filename, uid, gid);
		if (retval)
			dbg("chown(%s, %u, %u) failed with error '%s'", filename,
			    uid, gid, strerror(errno));
	}

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
static int sleep_for_dev(char *path)
{
	char filename[SYSFS_PATH_MAX + 6];
	int loop = SECONDS_TO_WAIT_FOR_DEV;
	int retval;

	strcpy(filename, sysfs_path);
	strcat(filename, path);
	strcat(filename, "/dev");

	while (loop--) {
		struct stat buf;

		dbg("looking for %s", filename);
		retval = stat(filename, &buf);
		if (!retval)
			goto exit;

		/* sleep for a second or two to give the kernel a chance to
		 * create the dev file */
		sleep(1);
	}
	retval = -ENODEV;
exit:
	return retval;
}

int udev_add_device(char *path, char *subsystem)
{
	struct sysfs_class_device *class_dev;
	struct udevice dev;
	int retval = -EINVAL;

	/* for now, the block layer is the only place where block devices are */
	if (strcmp(subsystem, "block") == 0)
		dev.type = 'b';
	else
		dev.type = 'c';

	retval = sleep_for_dev(path);
	if (retval)
		goto exit;

	class_dev = get_class_dev(path);
	if (class_dev == NULL)
		goto exit;

	retval = namedev_name_device(class_dev, &dev);
	if (retval)
		return retval;

	retval = get_major_minor(class_dev, &dev.major, &dev.minor);
	if (retval) {
		dbg("get_major_minor failed");
		goto exit;
	}

//	strcpy(dev.name, attr.name);
//	strcpy(dev.owner, attr.owner);
//	strcpy(dev.group, attr.group);
//	dev.mode = attr.mode;
	
	retval = udevdb_add_dev(path, &dev);
	if (retval != 0)
		dbg("udevdb_add_dev failed, but we are going to try to create the node anyway. "
		    "But remove might not work properly for this device.");

	sysfs_close_class_device(class_dev);

	dbg("name = %s", dev.name);
	retval = create_node(&dev);

exit:
	return retval;
}

