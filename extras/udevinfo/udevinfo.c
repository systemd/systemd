/*
 * udevinfo - fetches attributes for a device
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

#include "libsysfs.h"


# define VALUE_SIZE 200

char **main_argv;
char **main_envp;

static int print_all_attributes(char *path)
{
	struct dlist *attributes;
	struct sysfs_attribute *attr;
	struct sysfs_directory *sysfs_dir;
	char value[VALUE_SIZE];
	int len;
	int retval = 0;

	sysfs_dir = sysfs_open_directory(path);
	if (sysfs_dir == NULL)
		return -1;

	attributes = sysfs_get_dir_attributes(sysfs_dir);
	if (attributes == NULL) {
		retval = -1;
		goto exit;
	}

	dlist_for_each_data(attributes, attr, struct sysfs_attribute) {
		if (attr->value != NULL) {
			strncpy(value, attr->value, VALUE_SIZE);
			len = strlen(value);
			if (value[len-1] == '\n')
				value[len-1] = '\0';
			printf("  SYSFS_%s=\"%s\"\n", attr->name, value);
		}
	}
	printf("\n");

exit:
	sysfs_close_directory(sysfs_dir);

	return retval;
}

int main(int argc, char **argv, char **envp)
{
	main_argv = argv;
	main_envp = envp;
	struct sysfs_class_device *class_dev;
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_attribute *attr;
	struct sysfs_device *sysfs_device;
	char *path;
	int retval = 0;

	if (argc != 2) {
		printf("Usage: udevinfo <sysfs_device_path>\n");
		return -1;
	}
	path = argv[1];

	/*  get the class dev */
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		printf("couldn't get the class device\n");
		return -1;
	}

	/* read the 'dev' file for major/minor*/
	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr == NULL) {
		printf("couldn't get the \"dev\" file\n");
		retval = -1;
		goto exit;
	}
	printf("\ndevice '%s' has major:minor %s\n", class_dev->path, attr->value);
	sysfs_close_attribute(attr);

	/* open sysfs class device directory and print all attributes */
	printf("looking at class device '%s':\n", class_dev->path);
	if (print_all_attributes(class_dev->path) != 0) {
		printf("couldn't open class device directory\n");
		retval = -1;
		goto exit;
	}

	/* get the device (if parent exists use it instead) */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent != NULL) {
		//sysfs_close_class_device(class_dev);
		class_dev = class_dev_parent;
	}
	sysfs_device = sysfs_get_classdev_device(class_dev);
	if (sysfs_device != NULL) {
		printf("follow class device's \"device\" link '%s':\n", class_dev->path);
		printf("  BUS=\"%s\"\n", sysfs_device->bus);
		printf("  ID=\"%s\"\n", sysfs_device->bus_id);

		/* open sysfs device directory and print all attributes */
		print_all_attributes(sysfs_device->path);
		sysfs_close_device(sysfs_device);
	}

exit:
	//sysfs_close_class_device(class_dev);
	return retval;
}
