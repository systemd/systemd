/*
 * sysfs_class.c
 *
 * Generic class utility functions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003-2005
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
	if (dev) {
		if (dev->parent)
			sysfs_close_class_device(dev->parent);
		if (dev->sysdevice)
			sysfs_close_device(dev->sysdevice);
		if (dev->attrlist)
			dlist_destroy(dev->attrlist);
		free(dev);
	}
}

/**
 * alloc_class_device: mallocs and initializes new class device struct.
 * returns sysfs_class_device or NULL.
 */
static struct sysfs_class_device *alloc_class_device(void)
{
	struct sysfs_class_device *dev;

	dev = calloc(1, sizeof(struct sysfs_class_device));
	return dev;
}

/**
 * set_classdev_classname: Grabs classname from path
 * @cdev: class device to set
 * Returns nothing
 */
static void set_classdev_classname(struct sysfs_class_device *cdev)
{
	char *c, *e;
	int count = 0;

	c = strstr(cdev->path, SYSFS_CLASS_NAME);
	if (c == NULL) {
		c = strstr(cdev->path, SYSFS_BLOCK_NAME);
	} else {
		c = strstr(c, "/");
	}

	if (c == NULL)
		safestrcpy(cdev->classname, SYSFS_UNKNOWN);
	else {
		if (*c == '/')
			c++;
		e = c;
		while (e != NULL && *e != '/' && *e != '\0') {
			e++;
			count++;
		}
		strncpy(cdev->classname, c, count);
	}
}

/**
 * sysfs_open_class_device_path: Opens and populates class device
 * @path: path to class device.
 * returns struct sysfs_class_device with success and NULL with error.
 */
struct sysfs_class_device *sysfs_open_class_device_path(const char *path)
{
	struct sysfs_class_device *cdev;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	if ((sysfs_path_is_dir(path)) != 0) {
		dprintf("%s is not a valid path to a class device\n", path);
		return NULL;
	}
	cdev = alloc_class_device();
	if (!cdev) {
		dprintf("calloc failed\n");
		return NULL;
	}
	if (sysfs_get_name_from_path(path, cdev->name, SYSFS_NAME_LEN)) {
		errno = EINVAL;
		dprintf("Error getting class device name\n");
		sysfs_close_class_device(cdev);
		return NULL;
	}

	safestrcpy(cdev->path, path);
	if ((sysfs_remove_trailing_slash(cdev->path)) != 0) {
		dprintf("Invalid path to class device %s\n", cdev->path);
		sysfs_close_class_device(cdev);
		return NULL;
	}
	set_classdev_classname(cdev);

	return cdev;
}

/** 
 * get_blockdev_parent: Get the parent class device for a "block" subsystem 
 * 		device if present
 * @clsdev: block subsystem class device whose parent needs to be found
 * Returns 0 on success and 1 on error
 */
static int get_blockdev_parent(struct sysfs_class_device *clsdev)
{
	char parent_path[SYSFS_PATH_MAX];
	char *c;

	safestrcpy(parent_path, clsdev->path);
	c = strstr(parent_path, SYSFS_BLOCK_NAME);
	if (c == NULL) {
		dprintf("Class device %s does not belong to BLOCK subsystem\n",
				clsdev->name);
		return 1;
	}
	c += strlen(SYSFS_BLOCK_NAME);
	if (*c == '/')
		c++;
	else
		goto errout;

	/* validate whether the given class device is a partition or not */
	if ((strncmp(c, clsdev->name, strlen(clsdev->name))) == 0) {
		dprintf("%s not a partition\n", clsdev->name);
		return 1;
	}

	c = strchr(c, '/');
	if (c == NULL)
		goto errout;

	*c = '\0';

	clsdev->parent = sysfs_open_class_device_path(parent_path);
	if (!clsdev->parent) {
		dprintf("Error opening the parent class device at %s\n", 
								parent_path);
		return 1;
	}
	return 0;

errout:
	dprintf("Invalid path %s\n", clsdev->path);
	return 1;
}

/**
 * sysfs_get_classdev_parent: Retrieves the parent of a class device. 
 * 	eg., when working with hda1, this function can be used to retrieve the
 * 		sysfs_class_device for hda
 * 		
 * @clsdev: class device whose parent details are required.
 * Returns sysfs_class_device of the parent on success, NULL on failure
 */ 
struct sysfs_class_device *sysfs_get_classdev_parent
				(struct sysfs_class_device *clsdev)
{
	if (!clsdev) {
		errno = EINVAL;
		return NULL;
	}
	if (clsdev->parent)
		return (clsdev->parent);

	/*
	 * As of now, only block devices have a parent child heirarchy in sysfs
	 * We do not know, if, in the future, more classes will have a similar
	 * structure. Hence, we now call a specialized function for block and
	 * later we can add support functions for other subsystems as required.
	 */
	if (!(strncmp(clsdev->classname, SYSFS_BLOCK_NAME, 
					sizeof(SYSFS_BLOCK_NAME)))) {
		if ((get_blockdev_parent(clsdev)) == 0) 
			return (clsdev->parent);
	}
	return NULL;
}

/**
 * get_classdev_path: given the class and a device in the class, return the
 * 		absolute path to the device
 * @classname: name of the class
 * @clsdev: the class device
 * @path: buffer to return path
 * @psize: size of "path"
 * Returns 0 on SUCCESS or -1 on error
 */
static int get_classdev_path(const char *classname, const char *clsdev, 
		char *path, size_t len)
{
	if (!classname || !clsdev || !path) {
		errno = EINVAL;
		return -1;
	}
	if (sysfs_get_mnt_path(path, len) != 0) {
		dprintf("Error getting sysfs mount path\n");
		return -1;
	}
	if (strncmp(classname, SYSFS_BLOCK_NAME,
				sizeof(SYSFS_BLOCK_NAME)) == 0) {
		safestrcatmax(path, "/", len);
		safestrcatmax(path, SYSFS_BLOCK_NAME, len);
	} else {
		safestrcatmax(path, "/", len);
		safestrcatmax(path, SYSFS_CLASS_NAME, len);
		safestrcatmax(path, "/", len);
		safestrcatmax(path, classname, len);
	}
	safestrcatmax(path, "/", len);
	safestrcatmax(path, clsdev, len);
	return 0;
}

/**
 * sysfs_open_class_device: Locates a specific class_device and returns it.
 * Class_device must be closed using sysfs_close_class_device
 * @classname: Class to search
 * @name: name of the class_device
 * 
 * NOTE:
 * 	Call sysfs_close_class_device() to close the class device
 */
struct sysfs_class_device *sysfs_open_class_device
		(const char *classname, const char *name)
{
	char devpath[SYSFS_PATH_MAX];
	struct sysfs_class_device *cdev;

	if (!classname || !name) {
		errno = EINVAL;
		return NULL;
	}
	
	memset(devpath, 0, SYSFS_PATH_MAX);
	if ((get_classdev_path(classname, name, devpath, 
					SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to device %s on class %s\n",
							name, classname);
		return NULL;
	}

	cdev = sysfs_open_class_device_path(devpath);
	if (!cdev) {
		dprintf("Error getting class device %s from class %s\n",
				name, classname);
		return NULL;
	}
	return cdev;
}

/**
 * sysfs_get_classdev_attr: searches class device's attributes by name
 * @clsdev: class device to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference with success or NULL with error
 */
struct sysfs_attribute *sysfs_get_classdev_attr
		(struct sysfs_class_device *clsdev, const char *name)
{
	if (!clsdev || !name) {
		errno = EINVAL;
		return NULL;
	}
	return get_attribute(clsdev, (char *)name);
}

/**
 * sysfs_get_classdev_attributes: gets list of classdev attributes
 * @clsdev: class device whose attributes list is needed
 * returns dlist of attributes on success or NULL on error
 */
struct dlist *sysfs_get_classdev_attributes(struct sysfs_class_device *clsdev)
{
	if (!clsdev) {
		errno = EINVAL;
		return NULL;
	}
	return get_attributes_list(clsdev);
}

/**
 * sysfs_get_classdev_device: gets the sysfs_device associated with the
 * 	given sysfs_class_device
 * @clsdev: class device whose associated sysfs_device is needed
 * returns struct sysfs_device * on success or NULL on error
 */
struct sysfs_device *sysfs_get_classdev_device
		(struct sysfs_class_device *clsdev)
{
	char linkpath[SYSFS_PATH_MAX], devpath[SYSFS_PATH_MAX];

	if (!clsdev) {
		errno = EINVAL;
		return NULL;
	}

	if (clsdev->sysdevice)
		return clsdev->sysdevice;

	memset(linkpath, 0, SYSFS_PATH_MAX);
	safestrcpy(linkpath, clsdev->path);
	safestrcat(linkpath, "/device");
	if (!sysfs_path_is_link(linkpath)) {
		memset(devpath, 0, SYSFS_PATH_MAX);
		if (!sysfs_get_link(linkpath, devpath, SYSFS_PATH_MAX))
			clsdev->sysdevice = sysfs_open_device_path(devpath);
	}
	return clsdev->sysdevice;
}
