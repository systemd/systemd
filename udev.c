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


static char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}


static char *get_device(void)
{
	static char device[255];
	char *temp;

	temp = getenv("DEVPATH");
	if (temp == NULL)
		return NULL;
	strcpy(device, SYSFS_ROOT);
	strcat(device, temp);

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
static int get_major_minor (char *dev, int *major, int *minor)
{
	char filename[255];
	char line[20];
	char temp[3];
	int fd;
	int retval = 0;

	/* add the dev file to the directory and see if it's present */
	strncpy(filename, dev, sizeof(filename));
	strncat(filename, DEV_FILE, sizeof(filename));
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		dbg("Can't open %s", filename);
		return -ENODEV;
	}

	/* get the major/minor */
	retval = read(fd, line, sizeof(line));
	if (retval < 0) {
		dbg("read error on %s", dev);
		goto exit;
	}

	temp[0] = line[0];
	temp[1] = line[1];
	temp[2] = 0x00;
	*major = (int)strtol(&temp[0], NULL, 16);

	temp[0] = line[2];
	temp[1] = line[3];
	temp[2] = 0x00;
	*minor = (int)strtol(&temp[0], NULL, 16);

	dbg("found major = %d, minor = %d", *major, *minor);

	retval = 0;
exit:
	close(fd);
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
 * Again, this will live in the naming deamon
 */
static int get_mode(char *name, char *dev, int major, int minor)
{
	/* just default everyone to rw for the world! */
	return 0666;
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

static int remove_node(char *name)
{
	return 0;
}

static int do_it(char *action, char *name, char type, int major, int minor, int mode)
{
	if (strcmp(action, "add") == 0)
		return create_node(name, type, major, minor, mode);

	if (strcmp(action, "remove") == 0)
		return remove_node(name);

	dbg("Unknown action: %s", action);
	return -EINVAL;
}

int main(int argc, char *argv[])
{
	char *subsystem;
	char *action;
	char *device;
	char *name;
	char type;
	int major;
	int minor;
	int mode;
	int retval = -EINVAL;
	
	if (argc != 2) {
		dbg ("unknown number of arguments");
		goto exit;
	}

	/* for now, the block layer is the only place where block devices are */
	subsystem = argv[1];
	if (strcmp(subsystem, "block") == 0)
		type = 'b';
	else
		type = 'c';

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	device = get_device();
	if (!device) {
		dbg ("no device?");
		goto exit;
	}
	dbg("looking at %s", device);

	retval = get_major_minor(device, &major, &minor);
	if (retval) {
		dbg ("get_major_minor failed");
		goto exit;
	}

	name = get_name(device, major, minor);
	if (name == NULL) {
		dbg ("get_name failed");
		retval = -ENODEV;
		goto exit;
	}

	mode = get_mode(name, device, major, minor);
	if (mode < 0) {
		dbg ("get_mode failed");
		retval = -EINVAL;
		goto exit;
	}

	retval = do_it(action, name, type, major, minor, mode);
	if (retval) {
		dbg ("do_it failed");
		goto exit;
	}

	retval = 0;
exit:	
	return retval;
}

