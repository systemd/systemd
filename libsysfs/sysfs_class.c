/*
 * sysfs_class.c
 *
 * Generic class utility functions for libsysfs
 *
 * Copyright (C) 2003 International Business Machines, Inc.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#include "libsysfs.h"
#include "sysfs.h"

/**
 * sysfs_close_class_device: closes a single class device.
 * @dev: class device to close.
 */
void sysfs_close_class_device(struct sysfs_class_device *dev)
{
	if (dev != NULL) {
		if (dev->directory != NULL)
			sysfs_close_directory(dev->directory);
		if (dev->sysdevice != NULL)
			sysfs_close_device(dev->sysdevice);
		if (dev->driver != NULL)
			sysfs_close_driver(dev->driver);
		free(dev);
	}
}

/**
 * sysfs_close_class: close single class
 * @class: class structure
 */
void sysfs_close_class(struct sysfs_class *cls)
{
	struct sysfs_class_device *cur = NULL, *next = NULL;

	if (cls != NULL) {
		if (cls->directory != NULL)
			sysfs_close_directory(cls->directory);
		for (cur = cls->devices; cur != NULL; cur = next) {
			next = cur->next;
			sysfs_close_class_device(cur);
		}
		free(cls);
	}
}

/**
 * alloc_class_device: mallocs and initializes new class device struct.
 * returns sysfs_class_device or NULL.
 */
static struct sysfs_class_device *alloc_class_device(void)
{
	return (struct sysfs_class_device *)
				calloc(1, sizeof(struct sysfs_class_device));
}

/**
 * alloc_class: mallocs new class structure
 * returns sysfs_class struct or NULL
 */
static struct sysfs_class *alloc_class(void)
{
	return (struct sysfs_class *)calloc(1, sizeof(struct sysfs_class));
}

/**
 * open_class_dir: opens up sysfs class directory
 * returns sysfs_directory struct with success and NULL with error
 */
static struct sysfs_directory *open_class_dir(const char *name)
{
	struct sysfs_directory *classdir = NULL;
	char classpath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(classpath, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_mnt_path(classpath, SYSFS_PATH_MAX)) != 0) {
		dprintf(stderr, "Sysfs not supported on this system\n");
		return NULL;
	}

	strcat(classpath, SYSFS_CLASS_DIR);
	strcat(classpath, "/");
	strcat(classpath, name);
	classdir = sysfs_open_directory(classpath);
	if (classdir == NULL) {
		errno = EINVAL;
		dprintf(stderr,"Class %s not supported on this system\n",
			name);
		return NULL;
	}
	if ((sysfs_read_directory(classdir)) != 0) {
		dprintf(stderr, "Error reading %s class dir %s\n", name, 
			classpath);
		sysfs_close_directory(classdir);
		return NULL;
	}

	return classdir;
}

/**
 * sysfs_open_class_device: Opens and populates class device
 * @path: path to class device.
 * returns struct sysfs_class_device with success and NULL with error.
 */
struct sysfs_class_device *sysfs_open_class_device(const char *path)
{
	struct sysfs_class_device *cdev = NULL;
	struct sysfs_directory *dir = NULL, *cur = NULL;
	struct sysfs_dlink *curl = NULL;
	struct sysfs_device *sdev = NULL;
	struct sysfs_driver *drv = NULL;
	char temp[SYSFS_NAME_LEN];

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	cdev = alloc_class_device();
	if (cdev == NULL) {
		perror("malloc");
		return NULL;
	}
	memset(temp, 0, SYSFS_NAME_LEN);
	if ((sysfs_get_name_from_path(path, temp, SYSFS_NAME_LEN)) != 0) {
		errno = EINVAL;
		dprintf(stderr, "Invalid class device path %s\n", path);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	strcpy(cdev->name, temp);

	dir = sysfs_open_directory(path);
	if (dir == NULL) {
		dprintf(stderr, "Error opening class device at %s\n", path);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	if ((sysfs_read_directory(dir)) != 0) {
		dprintf(stderr, "Error reading class device at %s\n", path);
		sysfs_close_directory(dir);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	cdev->directory = dir;

	cur = cdev->directory->subdirs;
	while(cur != NULL) {
		sysfs_read_directory(cur);
		cur = cur->next;
	}
	/* get driver and device, if implemented */
	curl = cdev->directory->links;
	while (curl != NULL) {
		if (strncmp(curl->name, SYSFS_DEVICES_NAME, 6) == 0) {
			sdev = sysfs_open_device(curl->target->path);
			if (sdev != NULL) {
				cdev->sysdevice = sdev;
				if (cdev->driver != NULL) 
					sdev->driver = cdev->driver;
			}
		} else if (strncmp(curl->name, SYSFS_DRIVERS_NAME, 6) == 0) {
			drv = sysfs_open_driver(curl->target->path);
			if (drv != NULL) {
				cdev->driver = drv;
				if (cdev->sysdevice != NULL) 
					drv->device = cdev->sysdevice;
			}
		}
		curl = curl->next;
	}
	return cdev;
}

/**
 * add_dev_to_class: adds a class device to class list
 * @class: class to add the device
 * @dev: device to add
 */
static void add_dev_to_class(struct sysfs_class *cls, 
					struct sysfs_class_device *dev)
{
	if (cls != NULL && dev != NULL) {
		dev->next = cls->devices;
		cls->devices = dev;
	}
}

/**
 * get_all_class_devices: gets all devices for class
 * @class: class to get devices for
 * returns 0 with success and -1 with failure
 */
static int get_all_class_devices(struct sysfs_class *cls)
{
	struct sysfs_class_device *dev = NULL;
	struct sysfs_directory *cur = NULL, *next = NULL;

	if (cls == NULL || cls->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (cur = cls->directory->subdirs; cur != NULL; cur = next) {
		next = cur->next;
		dev = sysfs_open_class_device(cur->path);
		if (dev == NULL) {
			dprintf(stderr, "Error opening device at %s\n",
				cur->path);
			continue;
		}
		add_dev_to_class(cls, dev);
	}
			
	return 0;
}

/**
 * sysfs_open_class: opens specific class and all its devices on system
 * returns sysfs_class structure with success or NULL with error.
 */
struct sysfs_class *sysfs_open_class(const char *name)
{
	struct sysfs_class *cls = NULL;
	struct sysfs_directory *classdir = NULL;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	cls = alloc_class();
	if (cls == NULL) {
		perror("malloc");
		return NULL;
	}
	strcpy(cls->name, name);	
	classdir = open_class_dir(name);
	if (classdir == NULL) {
		dprintf(stderr,
			"Invalid class, %s not supported on this system\n",
			name);
		sysfs_close_class(cls);
		return NULL;
	}
	cls->directory = classdir;
	if ((get_all_class_devices(cls)) != 0) {
		dprintf(stderr, "Error reading %s class devices\n", name);
		sysfs_close_class(cls);
		return NULL;
	}

	return cls;
}
