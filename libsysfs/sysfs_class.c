/*
 * sysfs_class.c
 *
 * Generic class utility functions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003
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

void sysfs_close_cls_dev(void *dev)
{
	sysfs_close_class_device((struct sysfs_class_device *)dev);
}

/**
 * class_name_equal: compares class_devices' name
 * @a: class_name looking for
 * @b: sysfs_class_device being compared
 */
static int class_name_equal(void *a, void *b)
{
	if (a == NULL || b == NULL)
		return 0;

	if (strcmp(((unsigned char *)a), ((struct sysfs_class_device *)b)->name)
		== 0)
		return 1;

	return 0;
}

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
	if (cls != NULL) {
		if (cls->directory != NULL)
			sysfs_close_directory(cls->directory);
		if (cls->devices != NULL) 
			dlist_destroy(cls->devices);
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
static struct sysfs_directory *open_class_dir(const unsigned char *name)
{
	struct sysfs_directory *classdir = NULL;
	unsigned char classpath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(classpath, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_mnt_path(classpath, SYSFS_PATH_MAX)) != 0) {
		dprintf("Sysfs not supported on this system\n");
		return NULL;
	}

	strcat(classpath, SYSFS_CLASS_DIR);
	strcat(classpath, "/");
	strcat(classpath, name);
	classdir = sysfs_open_directory(classpath);
	if (classdir == NULL) {
		errno = EINVAL;
		dprintf("Class %s not supported on this system\n", name);
		return NULL;
	}
	if ((sysfs_read_directory(classdir)) != 0) {
		dprintf("Error reading %s class dir %s\n", name, classpath);
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
struct sysfs_class_device *sysfs_open_class_device(const unsigned char *path)
{
	struct sysfs_class_device *cdev = NULL;
	struct sysfs_directory *dir = NULL;
	struct sysfs_link *curl = NULL;
	struct sysfs_device *sdev = NULL;
	struct sysfs_driver *drv = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	cdev = alloc_class_device();
	if (cdev == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	if ((sysfs_get_name_from_path(path, cdev->name, SYSFS_NAME_LEN)) != 0) {
		errno = EINVAL;
		dprintf("Invalid class device path %s\n", path);
		sysfs_close_class_device(cdev);
		return NULL;
	}

	dir = sysfs_open_directory(path);
	if (dir == NULL) {
		dprintf("Error opening class device at %s\n", path);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	if ((sysfs_read_directory(dir)) != 0) {
		dprintf("Error reading class device at %s\n", path);
		sysfs_close_directory(dir);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	sysfs_read_all_subdirs(dir);
	cdev->directory = dir;
	strcpy(cdev->path, dir->path);

	/* get driver and device, if implemented */
	if (cdev->directory->links != NULL) {
		dlist_for_each_data(cdev->directory->links, curl,
				struct sysfs_link) {
			if (strncmp(curl->name, SYSFS_DEVICES_NAME, 6) == 0) {
				sdev = sysfs_open_device(curl->target);
				if (sdev != NULL) {
					cdev->sysdevice = sdev;
					if (cdev->driver != NULL) 
						strncpy(sdev->driver_name,
							cdev->driver->name, 
							SYSFS_NAME_LEN);
				}
			} else if (strncmp(curl->name, 
						SYSFS_DRIVERS_NAME, 6) == 0) {
				drv = sysfs_open_driver(curl->target);
				if (drv != NULL) {
					cdev->driver = drv;
					if (cdev->sysdevice != NULL) {
						strncpy(cdev->sysdevice->name,
								drv->name, 
								SYSFS_NAME_LEN);
						if (drv->devices == NULL)
							drv->devices = 
								dlist_new
								(sizeof(struct 
								sysfs_device));
						dlist_unshift(drv->devices, 
							cdev->sysdevice);
					}
				}
			}
		}
	}
	return cdev;
}

/**
 * get_all_class_devices: gets all devices for class
 * @class: class to get devices for
 * returns 0 with success and -1 with failure
 */
static int get_all_class_devices(struct sysfs_class *cls)
{
	struct sysfs_class_device *dev = NULL;
	struct sysfs_directory *cur = NULL;

	if (cls == NULL || cls->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (cls->directory->subdirs == NULL)
		return 0;
	dlist_for_each_data(cls->directory->subdirs, cur, 
			struct sysfs_directory) {
		dev = sysfs_open_class_device(cur->path);
		if (dev == NULL) {
			dprintf("Error opening device at %s\n",	cur->path);
			continue;
		}
		if (cls->devices == NULL)
			cls->devices = dlist_new_with_delete
					(sizeof(struct sysfs_class_device),
					 		sysfs_close_cls_dev);
		dlist_unshift(cls->devices, dev);
	}
	return 0;
}

/**
 * sysfs_open_class: opens specific class and all its devices on system
 * returns sysfs_class structure with success or NULL with error.
 */
struct sysfs_class *sysfs_open_class(const unsigned char *name)
{
	struct sysfs_class *cls = NULL;
	struct sysfs_directory *classdir = NULL;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	cls = alloc_class();
	if (cls == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	strcpy(cls->name, name);	
	classdir = open_class_dir(name);
	if (classdir == NULL) {
		dprintf("Invalid class, %s not supported on this system\n",
			name);
		sysfs_close_class(cls);
		return NULL;
	}
	cls->directory = classdir;
	strcpy(cls->path, classdir->path);
	if ((get_all_class_devices(cls)) != 0) {
		dprintf("Error reading %s class devices\n", name);
		sysfs_close_class(cls);
		return NULL;
	}

	return cls;
}

/**
 * sysfs_get_class_device: Get specific class device using the device's id
 * @class: class to find device on
 * @name: class name of the device
 */ 
struct sysfs_class_device *sysfs_get_class_device(struct sysfs_class *class,
					unsigned char *name)
{
	if (class == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return (struct sysfs_class_device *)dlist_find_custom(class->devices,
			name, class_name_equal);
}

/**
 * sysfs_open_class_device_by_name: Locates a specific class_device and returns it.
 * Class_device must be closed using sysfs_close_class_device
 * @classname: Class to search
 * @name: name of the class_device
 */
struct sysfs_class_device *sysfs_open_class_device_by_name
		(const unsigned char *classname, unsigned char *name)
{
	struct sysfs_class *class = NULL;
	struct sysfs_class_device *cdev = NULL, *rcdev = NULL;

	if (classname == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}
	
	class = sysfs_open_class(classname);
	if (class == NULL) {
		dprintf("Error opening class %s\n", classname);
		return NULL;
	}

	cdev = sysfs_get_class_device(class, name);
	if (cdev == NULL) {
		dprintf("Error getting class device %s from class %s\n",
				name, classname);
		sysfs_close_class(class);
		return NULL;
	}

	rcdev = sysfs_open_class_device(cdev->directory->path);
	if (rcdev == NULL) {
		dprintf("Error getting class device %s from class %s\n",
				name, classname);
		sysfs_close_class(class);
		return NULL;
	}
	sysfs_close_class(class);
	
	return rcdev;
}

/**
 * sysfs_get_classdev_attributes: returns a dlist of attributes for
 * 	the requested class_device
 * @cdev: sysfs_class_dev for which attributes are needed
 * returns a dlist of attributes if exists, NULL otherwise
 */
struct dlist *sysfs_get_classdev_attributes(struct sysfs_class_device *cdev)
{
	if (cdev == NULL || cdev->directory == NULL)
		return NULL;

	return (cdev->directory->attributes);
}

/**
 * sysfs_find_device_class: locates the device the device is on
 * @bus_id: device to look for
 * @classname: buffer to copy class name to
 * @bsize: size of buffer
 * returns 0 with success and -1 with error
 */
int sysfs_find_device_class(const unsigned char *bus_id, 
				unsigned char *classname, size_t bsize)
{
	unsigned char class[SYSFS_NAME_LEN], clspath[SYSFS_NAME_LEN];
	unsigned char *cls = NULL, *clsdev = NULL;
	struct dlist *clslist = NULL, *clsdev_list = NULL;

	if (bus_id == NULL || classname == NULL) {
		errno = EINVAL;
		return -1;
	}

	strcpy(class, SYSFS_CLASS_DIR);
	clslist = sysfs_open_subsystem_list(class);
	if (clslist != NULL) {
		dlist_for_each_data(clslist, cls, char) {
			memset(clspath, 0, SYSFS_NAME_LEN);
			strcpy(clspath, SYSFS_CLASS_DIR);
			strcat(clspath, "/");
			strcat(clspath, cls);
			clsdev_list = sysfs_open_subsystem_list(clspath);
			if (clsdev_list != NULL) {
				dlist_for_each_data(clsdev_list, 
							clsdev, char) {
					if (strcmp(bus_id, clsdev) == 0) {
						strncpy(classname, 
								cls, bsize);
						sysfs_close_list(clsdev_list);
						sysfs_close_list(clslist);
						return 0;
					}
				}
				sysfs_close_list(clsdev_list);
			}
		}
		sysfs_close_list(clslist);
	}
	return -1;
}

/**
 * sysfs_get_classdev_attr: searches class device's attributes by name
 * @clsdev: class device to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference with success or NULL with error
 */
struct sysfs_attribute *sysfs_get_classdev_attr
		(struct sysfs_class_device *clsdev, const unsigned char *name)
{
	struct sysfs_attribute *cur = NULL;

	if (clsdev == NULL || clsdev->directory == NULL ||
		clsdev->directory->attributes == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	cur = sysfs_get_directory_attribute(clsdev->directory,
						(unsigned char *)name);
	if (cur != NULL)
		return cur;

	return NULL;
}

/**
 * sysfs_write_classdev_attr: modify writable attribute value for the given
 * 				class device
 * @dev: class device name for which the attribute has to be changed
 * @attrib: attribute to change
 * @value: value to change to
 * @len: size of buffer at "value"
 * Returns 0 on success and -1 on error
 */
int sysfs_write_classdev_attr(unsigned char *dev, unsigned char *attrib,
				unsigned char *value, size_t len)
{
	struct sysfs_class_device *clsdev = NULL;
	struct sysfs_attribute *attribute = NULL;
	unsigned char class_name[SYSFS_NAME_LEN];

	if (dev == NULL || attrib == NULL || value == NULL) {
		errno = EINVAL;
		return -1;
	}
	
	memset(class_name, 0, SYSFS_NAME_LEN);
	if ((sysfs_find_device_class(dev, 
					class_name, SYSFS_NAME_LEN)) < 0) {
		dprintf("Class device %s not found\n", dev);
		return -1;
	}
	clsdev = sysfs_open_class_device_by_name(class_name, dev);
	if (clsdev == NULL) {
		dprintf("Error opening %s in class %s\n", dev, class_name);
		return -1;
	}
	attribute = sysfs_get_directory_attribute(clsdev->directory, attrib);
	if (attribute == NULL) {
		dprintf("Attribute %s not defined for device %s on class %s\n",
				attrib, dev, class_name);
		sysfs_close_class_device(clsdev);
		return -1;
	}
	if ((sysfs_write_attribute(attribute, value, len)) < 0) {
		dprintf("Error setting %s to %s\n", attrib, value);
		sysfs_close_class_device(clsdev);
		return -1;
	}
	sysfs_close_class_device(clsdev);
	return 0;
}

/**
 * sysfs_read_classdev_attr: read an attribute for a given class device
 * @dev: class device name for which the attribute has to be read
 * @attrib: attribute to read
 * @value: buffer to return value to user
 * @len: size of buffer at "value"
 * Returns 0 on success and -1 on error
 */
int sysfs_read_classdev_attr(unsigned char *dev, unsigned char *attrib,
				unsigned char *value, size_t len)
{
	struct sysfs_class_device *clsdev = NULL;
	struct sysfs_attribute *attribute = NULL;
	unsigned char class_name[SYSFS_NAME_LEN];

	if (dev == NULL || attrib == NULL || value == NULL) {
		errno = EINVAL;
		return -1;
	}
	
	memset(class_name, 0, SYSFS_NAME_LEN);
	if ((sysfs_find_device_class(dev, 
					class_name, SYSFS_NAME_LEN)) < 0) {
		dprintf("Class device %s not found\n", dev);
		return -1;
	}
	clsdev = sysfs_open_class_device_by_name(class_name, dev);
	if (clsdev == NULL) {
		dprintf("Error opening %s in class %s\n", dev, class_name);
		return -1;
	}
	attribute = sysfs_get_directory_attribute(clsdev->directory, attrib);
	if (attribute == NULL) {
		dprintf("Attribute %s not defined for device %s on class %s\n",
				attrib, dev, class_name);
		sysfs_close_class_device(clsdev);
		return -1;
	}
	if (attribute->len > len) {
		dprintf("Value length %d is greater that suppled buffer %d\n",
				attribute->len, len);
		sysfs_close_class_device(clsdev);
		return -1;
	}
	strncpy(value, attribute->value, attribute->len);
	value[(attribute->len)+1] = 0;
	sysfs_close_class_device(clsdev);
	return 0;
}
