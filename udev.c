/*
 * udev.c
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

static char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}


static char *get_device(void)
{
	char *device;

	device = getenv("DEVPATH");
	return device;
}

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
	char temp[3];
	int retval = 0;

	char *dev;

	dev = sysfs_get_value_from_attributes(class_dev->directory->attributes, "dev");
	if (dev == NULL)
		return -ENODEV;

	dbg("dev = %s", dev);

	temp[0] = dev[0];
	temp[1] = dev[1];
	temp[2] = 0x00;
	*major = (int)strtol(&temp[0], NULL, 16);

	temp[0] = dev[2];
	temp[1] = dev[3];
	temp[2] = 0x00;
	*minor = (int)strtol(&temp[0], NULL, 16);

	dbg("found major = %d, minor = %d", *major, *minor);

	retval = 0;
	return retval;
}

/*
 * Here would go a call to the naming deamon, to get the name we want to have
 * for this device.  But for now, let's just default to whatever the kernel is
 * calling the device as that will keep the "old-style" naming policy
 */
static char *get_name(char *dev, int major, int minor)
{
	static char name[100];
	char *temp;

	temp = strrchr(dev, '/');
	if (temp == NULL)
		return NULL;
	strncpy(name, &temp[1], sizeof(name));

	dbg("name is %s", name);

	return &name[0];
}

/*
 * We also want to add some permissions here, and possibly some symlinks
 */
static int create_node(char *name, char type, int major, int minor, int mode)
{
	char *argv[7];
	char mode_string[100];
	char type_string[3];
	char major_string[20];
	char minor_string[20];
	char filename[255];
	int retval = 0;

	strncpy(filename, UDEV_ROOT, sizeof(filename));
	strncat(filename, name, sizeof(filename));

	snprintf(mode_string, sizeof(mode_string), "--mode=%#o", mode);
	snprintf(type_string, sizeof(type_string), "%c", type);
	snprintf(major_string, sizeof(major_string), "%d", major);
	snprintf(minor_string, sizeof(minor_string), "%d", minor);
	
	argv[0] = MKNOD;
	argv[1] = mode_string;
	argv[2] = filename;
	argv[3] = type_string;
	argv[4] = major_string;
	argv[5] = minor_string;
	argv[6] = NULL;
	dbg ("executing %s %s %s %s %s %s",
		argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
	switch (fork()) {
		case 0:
			/* we are the child, so lets run the program */
			execv (MKNOD, argv);
			exit(0);
			break;
		case (-1):
			dbg ("fork failed.");
			retval = -EFAULT;
			break;
		default:
			break;
	}
	return retval;
}

/*
 * We also want to clean up any symlinks that were created in create_node()
 */
static int delete_node(char *name)
{
	char filename[255];

	strncpy(filename, UDEV_ROOT, sizeof(filename));
	strncat(filename, name, sizeof(filename));

	dbg("unlinking %s", filename);
	return unlink(filename);
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

static int add_device(char *device, char *subsystem)
{
	struct sysfs_class_device *class_dev;
	struct device_attr attr;
	//char *name;
	int major;
	int minor;
	char type;
	//int mode;
	int retval = -EINVAL;

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

static int remove_device(char *device)
{
	char *name;
	int retval = 0;

	name = get_name(device, 0, 0);
	if (name == NULL) {
		dbg ("get_name failed");
		retval = -ENODEV;
		goto exit;
	}

	return delete_node(name);

exit:
	return retval;
}
	
static int udev_init(void)
{
	int retval;

	retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
	dbg("sysfs_path = %s", sysfs_path);
	return retval;
}

int main(int argc, char *argv[])
{
	char *action;
	char *device;
	int retval = -EINVAL;
	
	if (argc != 2) {
		dbg ("unknown number of arguments");
		goto exit;
	}

	device = get_device();
	if (!device) {
		dbg ("no device?");
		goto exit;
	}
	dbg("looking at %s", device);

	/* we only care about class devices and block stuff */
	if (!strstr(device, "class") &&
	    !strstr(device, "block")) {
		dbg("not block or class");
		goto exit;
	}
	
	/* sleep for a second or two to give the kernel a chance to
	 * create the dev file
	 */
	sleep(1);

	udev_init();
	namedev_init();

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	if (strcmp(action, "add") == 0)
		return add_device(device, argv[1]);

	if (strcmp(action, "remove") == 0)
		return remove_device(device);

	dbg("Unknown action: %s", action);
	return -EINVAL;

	retval = 0;
exit:	
	return retval;
}

