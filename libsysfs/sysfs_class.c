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

static void sysfs_close_cls_dev(void *dev)
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
		if (dev->parent != NULL)
			sysfs_close_class_device(dev->parent);
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
 * set_classdev_classname: Grabs classname from path
 * @cdev: class device to set
 * Returns nothing
 */
static void set_classdev_classname(struct sysfs_class_device *cdev)
{
	unsigned char *c = NULL, *e = NULL;
	int count = 0;

	c = strstr(cdev->path, SYSFS_CLASS_NAME);
	if (c == NULL) {
		c = strstr(cdev->path, SYSFS_BLOCK_NAME);
	} else {
		c = strstr(c, "/");
	}

	if (c == NULL)
		strcpy(cdev->classname, SYSFS_UNKNOWN);
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
 * sysfs_open_class_device: Opens and populates class device
 * @path: path to class device.
 * returns struct sysfs_class_device with success and NULL with error.
 */
struct sysfs_class_device *sysfs_open_class_device(const unsigned char *path)
{
	struct sysfs_class_device *cdev = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((sysfs_path_is_dir(path)) != 0) {
		dprintf("%s is not a valid path to a class device\n", path);
		return NULL;
	}
	cdev = alloc_class_device();
	if (cdev == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	if ((sysfs_get_name_from_path(path, cdev->name, SYSFS_NAME_LEN)) != 0) {
		errno = EINVAL;
		dprintf("Error getting class device name\n");
		sysfs_close_class_device(cdev);
		return NULL;
	}

	strcpy(cdev->path, path);
	set_classdev_classname(cdev);

	return cdev;
}

/**
 * sysfs_get_class_devices: gets all devices for class
 * @class: class to get devices for
 * returns dlist of class_devices with success and NULL with error
 */
struct dlist *sysfs_get_class_devices(struct sysfs_class *cls)
{
	struct sysfs_class_device *dev = NULL;
	struct sysfs_directory *cur = NULL;

	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (cls->directory == NULL) {
		cls->directory = sysfs_open_directory(cls->path);
		if (cls->directory == NULL) 
			return NULL;
	}

	if ((sysfs_read_dir_subdirs(cls->directory) != 0) 
	    || cls->directory->subdirs == NULL)
		return NULL;

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
	return cls->devices;
}

/**
 * sysfs_open_class: opens specific class and all its devices on system
 * returns sysfs_class structure with success or NULL with error.
 */
struct sysfs_class *sysfs_open_class(const unsigned char *name)
{
	struct sysfs_class *cls = NULL;
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

	if (sysfs_trailing_slash(classpath) == 0)
		strcat(classpath, "/");

	/* 
	 * We shall now treat "block" also as a class. Hence, check here
	 * if "name" is "block" and proceed accordingly
	 */
	if (strcmp(name, SYSFS_BLOCK_NAME) == 0) {
		strcat(classpath, SYSFS_BLOCK_NAME);
	} else {
		strcat(classpath, SYSFS_CLASS_NAME);
		strcat(classpath, "/");
		strcat(classpath, name);
	}
	if ((sysfs_path_is_dir(classpath)) != 0) {
		dprintf("Class %s not found on the system\n", name);
		return NULL;
	}

	cls = alloc_class();
	if (cls == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	strcpy(cls->name, name);	
	strcpy(cls->path, classpath);
	
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
	struct dlist *devlist = NULL;
	
	if (class == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (class->devices == NULL) {
		class->devices = sysfs_get_class_devices(class);
		if (devlist == NULL) 
			return NULL;
	}
	return (struct sysfs_class_device *)dlist_find_custom(class->devices,
			name, class_name_equal);
}

/**
 * sysfs_get_classdev_device: returns the sysfs_device corresponding to
 * 		sysfs_class_device, if present
 * @clsdev: class device whose sysfs_device is required
 * Returns sysfs_device on success, NULL on error or if device is not
 * implemented
 */ 
struct sysfs_device *sysfs_get_classdev_device
			(struct sysfs_class_device *clsdev)
{
	struct sysfs_link *devlink = NULL;
	
	if (clsdev == NULL) {
		errno = EINVAL;
		return NULL;
	}
	
	if (clsdev->sysdevice != NULL)
		return (clsdev->sysdevice);
	
	if (clsdev->directory == NULL) {
		clsdev->directory = sysfs_open_directory(clsdev->path);
		if (clsdev->directory == NULL)
			return NULL;
	}
	devlink = sysfs_get_directory_link(clsdev->directory, "device");
	if (devlink == NULL) 
		return NULL;

	clsdev->sysdevice = sysfs_open_device(devlink->target);
	if (clsdev->sysdevice == NULL)
		return NULL;
	if (clsdev->driver != NULL) 
		strcpy(clsdev->sysdevice->driver_name, clsdev->driver->name);

	return (clsdev->sysdevice);
}
				
/**
 * sysfs_get_classdev_driver: returns the sysfs_driver corresponding to
 * 		sysfs_class_device, if present
 * @clsdev: class device whose sysfs_device is required
 * Returns sysfs_driver on success, NULL on error or if driver is not
 * implemented
 */ 
struct sysfs_driver *sysfs_get_classdev_driver
			(struct sysfs_class_device *clsdev)
{
	struct sysfs_link *drvlink = NULL;
	
	if (clsdev == NULL) {
		errno = EINVAL;
		return NULL;
	}
	
	if (clsdev->driver != NULL)
		return (clsdev->driver);
	
	if (clsdev->directory == NULL) {
		clsdev->directory = sysfs_open_directory(clsdev->path);
		if (clsdev->directory == NULL)
			return NULL;
	}
	drvlink = sysfs_get_directory_link(clsdev->directory, "driver");
	if (drvlink != NULL) {
		clsdev->driver = sysfs_open_driver(drvlink->target);
		if (clsdev->driver == NULL)
			return NULL;
			
	}
	return (clsdev->driver);
}
	
/* 
 * get_blockdev_parent: Get the parent class device for a "block" subsystem 
 * 		device if present
 * @clsdev: block subsystem class device whose parent needs to be found
 * Returns 0 on success and 1 on error
 */
static int get_blockdev_parent(struct sysfs_class_device *clsdev)
{
	unsigned char parent_path[SYSFS_PATH_MAX], value[256], *c = NULL;
	
	memset(parent_path, 0, SYSFS_PATH_MAX);
	strcpy(parent_path, clsdev->path);

	c = strstr(parent_path, SYSFS_BLOCK_NAME);
	if (c == NULL) {
		dprintf("Class device %s does not belong to BLOCK subsystem",
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
	
	/* Now validate if the parent has the "dev" attribute */
	memset(value, 0, 256);
	strcat(parent_path, "/dev");
	if ((sysfs_read_attribute_value(parent_path, value, 256)) != 0) {
		dprintf("Block device %s does not have a parent\n", 
							clsdev->name);
		return 1;
	}
		
	c = strrchr(parent_path, '/');
	if (c == NULL)
		goto errout;

	*c = '\0';
	clsdev->parent = sysfs_open_class_device(parent_path);
	if (clsdev->parent == NULL) {
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
	if (clsdev == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (clsdev->parent != NULL)
		return (clsdev->parent);
	
	/* 
	 * As of now, only block devices have a parent child heirarchy in sysfs
	 * We do not know, if, in the future, more classes will have a similar
	 * structure. Hence, we now call a specialized function for block and
	 * later we can add support functions for other subsystems as required.
	 */ 
	if (!(strcmp(clsdev->classname, SYSFS_BLOCK_NAME))) {
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
static int get_classdev_path(const unsigned char *classname, 
		const unsigned char *clsdev, unsigned char *path, size_t len)
{
	if (classname == NULL || clsdev == NULL || path == NULL) {
		errno = EINVAL;
		return -1;
	}
        if (sysfs_get_mnt_path(path, len) != 0) {
                dprintf("Error getting sysfs mount path\n");
                return -1;
	}

	if (sysfs_trailing_slash(path) == 0)
		strcat(path, "/");

	if (strcmp(classname, SYSFS_BLOCK_NAME) == 0) {
		strcat(path, SYSFS_BLOCK_NAME);
	} else {
		strcat(path, SYSFS_CLASS_NAME);
		strcat(path, "/");
		strcat(path, classname);
	}
	strcat(path, "/");
	strcat(path, clsdev);
	return 0;
}

/**
 * sysfs_open_class_device_by_name: Locates a specific class_device and returns it.
 * Class_device must be closed using sysfs_close_class_device
 * @classname: Class to search
 * @name: name of the class_device
 * 
 * NOTE:
 * 	Call sysfs_close_class_device() to close the class device
 */
struct sysfs_class_device *sysfs_open_class_device_by_name
		(const unsigned char *classname, const unsigned char *name)
{
	unsigned char devpath[SYSFS_PATH_MAX];
	struct sysfs_class_device *cdev = NULL;

	if (classname == NULL || name == NULL) {
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
	
	cdev = sysfs_open_class_device(devpath);
	if (cdev == NULL) {
		dprintf("Error getting class device %s from class %s\n",
				name, classname);
		return NULL;
	}
	return cdev;
}

/**
 * sysfs_get_classdev_attributes: returns a dlist of attributes for
 * 	the requested class_device
 * @cdev: sysfs_class_dev for which attributes are needed
 * returns a dlist of attributes if exists, NULL otherwise
 */
struct dlist *sysfs_get_classdev_attributes(struct sysfs_class_device *cdev)
{
	if (cdev == NULL)
		return NULL;

	if (cdev->directory == NULL) {
		cdev->directory = sysfs_open_directory(cdev->path);
		if (cdev->directory == NULL) 
			return NULL;
	}
	if (cdev->directory->attributes == NULL) {
		if ((sysfs_read_dir_attributes(cdev->directory)) != 0) {
			dprintf("Error reading attributes for directory %s\n",
							cdev->directory->path);
			return NULL;
		}
	} else {
		if ((sysfs_path_is_dir(cdev->path)) != 0) {
			dprintf("Class device at %s no longer exists\n", 
							cdev->path);
			return NULL;
		}
		if ((sysfs_refresh_attributes
					(cdev->directory->attributes)) != 0) {
			dprintf("Error refreshing classdev attributes\n");
			return NULL;
		}
	}
	return (cdev->directory->attributes);
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
	struct sysfs_directory *sdir = NULL;
	struct dlist *attrlist = NULL;
	
	if (clsdev == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}
	/* 
	 * First, see if it's in the current directory. Then look at 
	 * subdirs since class devices can have subdirs of attributes.
	 */ 
	attrlist = sysfs_get_classdev_attributes(clsdev);
	if (attrlist == NULL)
		return NULL;
	cur = sysfs_get_directory_attribute(clsdev->directory,
						(unsigned char *)name);
	if (cur != NULL)
		return cur;

	if (clsdev->directory->subdirs == NULL) 
		if ((sysfs_read_dir_subdirs(clsdev->directory)) != 0 ||
		    clsdev->directory->subdirs == NULL) 
			return NULL;

	dlist_for_each_data(clsdev->directory->subdirs, sdir,
				struct sysfs_directory) {
		cur = sysfs_get_directory_attribute(sdir, 
						(unsigned char *)name);
		if (cur != NULL)
			return cur;
	}
		
	return NULL;
}

/**
 * sysfs_open_classdev_attr: read an attribute for a given class device
 * @classname: name of the class on which to look
 * @dev: class device name for which the attribute has to be read
 * @attrib: attribute to read
 * Returns sysfs_attribute * on SUCCESS and NULL on error
 * 
 * NOTE:
 * 	A call to sysfs_close_attribute() is required to close the
 * 	attribute returned and to free memory
 */
struct sysfs_attribute *sysfs_open_classdev_attr(const unsigned char *classname,
		const unsigned char *dev, const unsigned char *attrib)
{
	struct sysfs_attribute *attribute = NULL;
	unsigned char path[SYSFS_PATH_MAX];

	if (classname == NULL || dev == NULL || attrib == NULL) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	if ((get_classdev_path(classname, dev, path, SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to device %s on class %s\n",
						dev, classname);
		return NULL;
	}
	strcat(path, "/");
	strcat(path, attrib);
	attribute = sysfs_open_attribute(path);
	if (attribute == NULL) {
		dprintf("Error opening attribute %s on class device %s\n",
				attrib, dev);
		return NULL;
	}
	if ((sysfs_read_attribute(attribute)) != 0) {
		dprintf("Error reading attribute %s for class device %s\n",
				attrib, dev);
		sysfs_close_attribute(attribute);
		return NULL;
	}
	return attribute;
}
