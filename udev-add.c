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
#include "libsysfs/libsysfs.h"


static char sysfs_path[SYSFS_PATH_MAX];

/* 
 * Right now the major/minor of a device is stored in a file called
 * "dev" in sysfs.
 * The number is stored as:
 * 	MMmm
 * 		MM is the major
 * 		mm is the minor
 * 		The value is in hex.
 * Yes, this will probably change when we go to a bigger major/minor
 * range, and will have to be changed at that time.
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
static int create_node(char *name, char type, int major, int minor, int mode)
{
	char filename[255];
	int retval = 0;
	strncpy(filename, UDEV_ROOT, sizeof(filename));
	strncat(filename, name, sizeof(filename));
	if (type == 'b') {
	       mode |= S_IFBLK;
    	} else if ((type == 'c') || (type == 'u')){
	        mode |= S_IFCHR;
    	} else if ( type == 'p') {
       		 mode |= S_IFIFO;
    	} else {
       		dbg("unknown node type %c\n", type);
       		return -1;
 	}

	retval = mknod(filename,mode,makedev(major,minor));
	return retval;
		
}

struct sysfs_class_device *get_class_dev(char *device_name)
{
	char dev_path[SYSFS_PATH_MAX];
	struct sysfs_class_device *class_dev;

	strcpy(dev_path, sysfs_path);
	strcat(dev_path, device_name);

	dbg("looking at %s", dev_path);

	/* open up the sysfs class device for this thing... */
	class_dev = sysfs_open_class_device(dev_path);
	if (class_dev == NULL) {
		dbg ("sysfs_open_class_device failed");
		return NULL;
	}
	dbg("class_dev->name = %s", class_dev->name);

	return class_dev;
}

static int udev_init(void)
{
	int retval;

	retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
	dbg("sysfs_path = %s", sysfs_path);
	return retval;
}

int udev_add_device(char *device, char *subsystem)
{
	struct sysfs_class_device *class_dev;
	struct device_attr attr;
	//char *name;
	int major;
	int minor;
	char type;
	//int mode;
	int retval = -EINVAL;

	/* sleep for a second or two to give the kernel a chance to
	 * create the dev file
	 */
	sleep(1);

	udev_init();

	/* for now, the block layer is the only place where block devices are */
	if (strcmp(subsystem, "block") == 0)
		type = 'b';
	else
		type = 'c';

	class_dev = get_class_dev(device);
	if (class_dev == NULL)
		goto exit;

	retval = namedev_name_device(class_dev, &attr);
	if (retval)
		return retval;

	retval = get_major_minor(class_dev, &major, &minor);
	if (retval) {
		dbg ("get_major_minor failed");
		goto exit;
	}

	sysfs_close_class_device(class_dev);

	return create_node(attr.name, type, major, minor, attr.mode);

exit:
	return retval;
}

