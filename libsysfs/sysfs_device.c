/*
 * sysfs_device.c
 *
 * Generic device utility functions for libsysfs
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

static int confirm_device_bus(struct sysfs_device *dev, 
				unsigned char *busname, unsigned char *bus_id)
{
        struct sysfs_link *devlink = NULL;
        unsigned char devpath[SYSFS_PATH_MAX];
	int result = 0;

        if (busname == NULL || bus_id == NULL)
                return -1;

        if (sysfs_get_mnt_path(devpath, SYSFS_PATH_MAX) != 0)
                return -1;

        strcat(devpath, SYSFS_BUS_DIR);
        strcat(devpath, "/");
        strcat(devpath, busname);
        strcat(devpath, SYSFS_DEVICES_DIR);
        strcat(devpath, "/");
        strcat(devpath, bus_id);

	devlink = sysfs_open_link(devpath);
	if (devlink == NULL)
		return -1;

	if (strcmp(devlink->target, dev->path) == 0)
		result++;
	sysfs_close_link(devlink);
	return result;
}

/**
 * get_device_bus: retrieves the bus name the device is on, checks path to
 *	bus' link to make sure it has correct device.
 * @dev: device to get busname.
 * returns 0 with success and -1 with error.
 */
static int get_device_bus(struct sysfs_device *dev)
{
	unsigned char subsys[SYSFS_NAME_LEN], *bus = NULL, *curdev = NULL;
	struct dlist *buslist = NULL, *device_list = NULL;

	if (dev == NULL) {
		errno = EINVAL;
		return -1;
	}

	strcpy(subsys, SYSFS_BUS_DIR);  /* subsys = /bus */
	buslist = sysfs_open_subsystem_list(subsys);
	if (buslist != NULL) {
		dlist_for_each_data(buslist, bus, char) {
			device_list = sysfs_open_bus_devices_list(bus);
			if (device_list != NULL) {
				dlist_for_each_data(device_list,
							curdev, char) {
					if (strcmp(dev->bus_id, curdev) == 0
					    && confirm_device_bus(dev, bus,
					    curdev) > 0) {
						strcpy(dev->bus, bus);
                                                sysfs_close_list(device_list);
                                                sysfs_close_list(buslist);
                                                return 0;
                                        }
                                }
                        sysfs_close_list(device_list);
                        }
                }
                sysfs_close_list(buslist);
        }
        return -1;
}

/**
 * sysfs_close_device_tree: closes every device in the supplied tree, 
 * 	closing children only.
 * @devroot: device root of tree.
 */
static void sysfs_close_device_tree(struct sysfs_device *devroot)
{
	if (devroot != NULL) {
		if (devroot->children != NULL) {
			struct sysfs_device *child = NULL;

			dlist_for_each_data(devroot->children, child,
					struct sysfs_device) {
				sysfs_close_device_tree(child);
			}
		}
		sysfs_close_device(devroot);
	}
}

/**
 * sysfs_del_device: routine for dlist integration
 */
static void sysfs_del_device(void *dev)
{
	sysfs_close_device((struct sysfs_device *)dev);
}

/**
 * sysfs_close_dev_tree: routine for dlist integration
 */
static void sysfs_close_dev_tree(void *dev)
{
	sysfs_close_device_tree((struct sysfs_device *)dev);
}

/**
 * sysfs_close_device: closes and cleans up a device
 * @dev = device to clean up
 */
void sysfs_close_device(struct sysfs_device *dev)
{
	if (dev != NULL) {
		if (dev->directory != NULL)
			sysfs_close_directory(dev->directory);
		if (dev->children != NULL && dev->children->count == 0)
			dlist_destroy(dev->children);
		free(dev);
	}
}

/**
 * alloc_device: allocates and initializes device structure
 * returns struct sysfs_device
 */
static struct sysfs_device *alloc_device(void)
{
	return (struct sysfs_device *)calloc(1, sizeof(struct sysfs_device));
}

/**
 * sysfs_get_device_attr: searches dev's attributes by name
 * @dev: device to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference with success or NULL with error.
 */
struct sysfs_attribute *sysfs_get_device_attr(struct sysfs_device *dev,
						const unsigned char *name)
{
	struct sysfs_attribute *cur = NULL;

	if (dev == NULL || dev->directory == NULL 
	    || dev->directory->attributes == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}
	
	cur = sysfs_get_directory_attribute(dev->directory, 
			(unsigned char *)name);
	if (cur != NULL)
		return cur;

	return NULL;
}

/**
 * sysfs_open_device: opens and populates device structure
 * @path: path to device, this is the /sys/devices/ path
 * returns sysfs_device structure with success or NULL with error
 */
struct sysfs_device *sysfs_open_device(const unsigned char *path)
{
	struct sysfs_device *dev = NULL;
	struct sysfs_directory *sdir = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	dev = alloc_device();	
	if (dev == NULL) {
		dprintf("Error allocating device at %s\n", path);
		return NULL;
	}
	sdir = sysfs_open_directory(path);
	if (sdir == NULL) {
		dprintf("Invalid device at %s\n", path);
		errno = EINVAL;
		sysfs_close_device(dev);
		return NULL;
	}
	if ((sysfs_read_directory(sdir)) != 0) {
		dprintf("Error reading device directory at %s\n", path);
		sysfs_close_directory(sdir);
		sysfs_close_device(dev);
		return NULL;
	}
	dev->directory = sdir;
	strcpy(dev->bus_id, sdir->name);
	strcpy(dev->path, sdir->path);

	/* 
	 * The "name" attribute no longer exists... return the device's
	 * sysfs representation instead, in the "dev->name" field, which
	 * implies that the dev->name and dev->bus_id contain same data.
	 */
	strncpy(dev->name, sdir->name, SYSFS_NAME_LEN);
	
	if (get_device_bus(dev) != 0)
		strcpy(dev->bus, SYSFS_UNKNOWN);

	return dev;
}

/**
 * sysfs_open_device_tree: opens root device and all of its children,
 *	creating a tree of devices. Only opens children.
 * @path: sysfs path to devices
 * returns struct sysfs_device and its children with success or NULL with
 *	error.
 */
static struct sysfs_device *sysfs_open_device_tree(const unsigned char *path)
{
	struct sysfs_device *rootdev = NULL, *new = NULL;
	struct sysfs_directory *cur = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	rootdev = sysfs_open_device(path);
	if (rootdev == NULL) {
		dprintf("Error opening root device at %s\n", path);
		return NULL;
	}
	if (rootdev->directory->subdirs != NULL) {
		dlist_for_each_data(rootdev->directory->subdirs, cur,
				struct sysfs_directory) {
			new = sysfs_open_device_tree(cur->path);
			if (new == NULL) {
				dprintf("Error opening device tree at %s\n",
					cur->path);
				sysfs_close_device_tree(rootdev);
				return NULL;
			}
			if (rootdev->children == NULL)
				rootdev->children = dlist_new_with_delete
					(sizeof(struct sysfs_device),
					sysfs_del_device);
			dlist_unshift(rootdev->children, new);
		}
	}

	return rootdev;
}

/**
 * sysfs_close_root_device: closes root and all devices
 * @root: root device to close
 */
void sysfs_close_root_device(struct sysfs_root_device *root)
{
	if (root != NULL) {
		if (root->devices != NULL)
			dlist_destroy(root->devices);
		if (root->directory != NULL)
			sysfs_close_directory(root->directory);
		free(root);
	}
}

/**
 * open_root_device_dir: opens up sysfs_directory for specific root dev
 * @name: name of root
 * returns struct sysfs_directory with success and NULL with error
 */
static struct sysfs_directory *open_root_device_dir(const unsigned char *name)
{
	struct sysfs_directory *rdir = NULL;
	unsigned char rootpath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(rootpath, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(rootpath, SYSFS_PATH_MAX) != 0) {
		dprintf ("Sysfs not supported on this system\n");
		return NULL;
	}

	strcat(rootpath, SYSFS_DEVICES_DIR);
	strcat(rootpath, "/");
	strcat(rootpath, name);
	rdir = sysfs_open_directory(rootpath);
	if (rdir == NULL) {
		errno = EINVAL;
		dprintf ("Root device %s not supported on this system\n",
			name);
		return NULL;
	}
	if (sysfs_read_directory(rdir) != 0) {
		dprintf ("Error reading %s root device at dir %s\n", name,
			rootpath);
		sysfs_close_directory(rdir);
		return NULL;
	}
	
	return rdir;
}

/**
 * get_all_root_devices: opens up all the devices under this root device
 * @root: root device to open devices for
 * returns 0 with success and -1 with error
 */
static int get_all_root_devices(struct sysfs_root_device *root)
{
	struct sysfs_device *dev = NULL;
	struct sysfs_directory *cur = NULL;

	if (root == NULL || root->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (root->directory->subdirs == NULL)
		return 0;

	dlist_for_each_data(root->directory->subdirs, cur,
			struct sysfs_directory) {
		dev = sysfs_open_device_tree(cur->path);
		if (dev == NULL) {
			dprintf ("Error opening device at %s\n", cur->path);
			continue;
		}
		if (root->devices == NULL)
			root->devices = dlist_new_with_delete
				(sizeof(struct sysfs_device), 
				sysfs_close_dev_tree);
		dlist_unshift(root->devices, dev);
	}

	return 0;
}

/**
 * sysfs_open_root_device: opens sysfs devices root and all of its
 *	devices.
 * @name: name of /sys/devices/root to open
 * returns struct sysfs_root_device if success and NULL with error
 */
struct sysfs_root_device *sysfs_open_root_device(const unsigned char *name)
{
	struct sysfs_root_device *root = NULL;
	struct sysfs_directory *rootdir = NULL;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	root = (struct sysfs_root_device *)calloc
					(1, sizeof(struct sysfs_root_device));
	if (root == NULL) {
		dprintf("calloc failure\n");
		return NULL;
	}
	rootdir = open_root_device_dir(name);
	if (rootdir == NULL) {
		dprintf ("Invalid root device, %s not supported\n", name);
		sysfs_close_root_device(root);
		return NULL;
	}
	strcpy(root->path, rootdir->path);
	root->directory = rootdir;
	if (get_all_root_devices(root) != 0) {
		dprintf ("Error retrieving devices for root %s\n", name);
		sysfs_close_root_device(root);
		return NULL;
	}

	return root;
}

/**
 * sysfs_get_device_attributes: returns a dlist of attributes corresponding to
 * 	the specific device
 * @device: struct sysfs_device * for which attributes are to be returned
 */
struct dlist *sysfs_get_device_attributes(struct sysfs_device *device)
{
	if (device == NULL || device->directory == NULL) 
		return NULL;

	return (device->directory->attributes);
}

/**
 * get_device_absolute_path: looks up the bus the device is on, gets 
 * 		absolute path to the device
 * @device: device for which path is needed
 * @path: buffer to store absolute path
 * @psize: size of "path"
 * Returns 0 on success -1 on failure
 */
static int get_device_absolute_path(const unsigned char *device,
		const unsigned char *bus, unsigned char *path, size_t psize)
{
	unsigned char bus_path[SYSFS_NAME_LEN];

	if (device == NULL || path == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(bus_path, 0, SYSFS_NAME_LEN);
	if (sysfs_get_mnt_path(bus_path, SYSFS_PATH_MAX) != 0) {
		dprintf ("Sysfs not supported on this system\n");
		return -1;
	}
	strcat(bus_path, SYSFS_BUS_DIR);
	strcat(bus_path, "/");
	strcat(bus_path, bus);
	strcat(bus_path, SYSFS_DEVICES_DIR);
	strcat(bus_path, "/");
	strcat(bus_path, device);
	/*
	 * We now are at /sys/bus/"bus_name"/devices/"device" which is a link.
	 * Now read this link to reach to the device.
	 */ 
	if ((sysfs_get_link(bus_path, path, SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to device %s\n", device);
		return -1;
	}
	return 0;
}

/**
 * sysfs_open_device_by_id: open a device by id (use the "bus" subsystem)
 * @bus_id: bus_id of the device to open - has to be the "bus_id" in 
 * 		/sys/bus/xxx/devices
 * @bus: bus the device belongs to
 * @bsize: size of the bus buffer
 * returns struct sysfs_device if found, NULL otherwise
 * NOTE: 
 * 1. Use sysfs_close_device to close the device
 * 2. Bus the device is on must be supplied
 * 	Use sysfs_find_device_bus to get the bus name
 */
struct sysfs_device *sysfs_open_device_by_id(const unsigned char *bus_id, 
		const unsigned char *bus, size_t bsize)
{
	char sysfs_path[SYSFS_PATH_MAX];
	struct sysfs_device *device = NULL;

	if (bus_id == NULL || bus == NULL) {
		errno = EINVAL;
		return NULL;
	}
	memset(sysfs_path, 0, SYSFS_PATH_MAX);
	if ((get_device_absolute_path(bus_id, bus, sysfs_path, 
						SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to device %s\n", bus_id);
		return NULL;
	}
	
	device = sysfs_open_device(sysfs_path);
	if (device == NULL) {
		dprintf("Error opening device %s\n", bus_id);
		return NULL;
	}

	return device;
}

/*
 * sysfs_open_device_attr: open the given device's attribute
 * @bus: Bus on which to look
 * @dev_id: device for which attribute is required
 * @attrname: name of the attribute to look for
 * Returns struct sysfs_attribute on success and NULL on failure
 * 
 * NOTE:
 * 	A call to sysfs_close_attribute() is required to close
 * 	the attribute returned and free memory. 
 */
struct sysfs_attribute *sysfs_open_device_attr(const unsigned char *bus,
		const unsigned char *bus_id, const unsigned char *attrib)
{
	struct sysfs_attribute *attribute = NULL;
	unsigned char devpath[SYSFS_PATH_MAX];
	
	if (bus == NULL || bus_id == NULL || attrib == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(devpath, 0, SYSFS_PATH_MAX);
	if ((get_device_absolute_path(bus_id, bus, devpath, 
					SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to device %s\n", bus_id);
		return NULL;
	}
	strcat(devpath, "/");
	strcat(devpath, attrib);
	attribute = sysfs_open_attribute(devpath);
	if (attribute == NULL) {
		dprintf("Error opening attribute %s for device %s\n",
				attrib, bus_id);
		return NULL;
	}
	if ((sysfs_read_attribute(attribute)) != 0) {
		dprintf("Error reading attribute %s for device %s\n",
				attrib, bus_id);
		sysfs_close_attribute(attribute);
		return NULL;
	}
	return attribute;
}

