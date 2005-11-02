/*
 * sysfs_device.c
 *
 * Generic device utility functions for libsysfs
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
 * get_dev_driver: fills in the dev->driver_name field 
 * Returns 0 on SUCCESS and -1 on error
 */
static int get_dev_driver(struct sysfs_device *dev)
{
	char path[SYSFS_PATH_MAX];
	char devpath[SYSFS_PATH_MAX];

	if (!dev) {
		errno = EINVAL;
		return -1;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	memset(devpath, 0, SYSFS_PATH_MAX);
	safestrcpymax(path, dev->path, SYSFS_PATH_MAX);
	safestrcatmax(path, "/driver", SYSFS_PATH_MAX);
	if (!sysfs_path_is_link(path)) {
		if (!sysfs_get_link(path, devpath, SYSFS_PATH_MAX)) {
			if (sysfs_get_name_from_path(devpath, 
					dev->driver_name, SYSFS_NAME_LEN))
				return -1;
		}
		return 0;
	}
	return -1;
}

/**
 * sysfs_get_device_bus: retrieves the bus name the device is on, checks path 
 * 	to bus' link to make sure it has correct device.
 * @dev: device to get busname.
 * returns 0 with success and -1 with error.
 */
int sysfs_get_device_bus(struct sysfs_device *dev)
{
	char devpath[SYSFS_PATH_MAX];
	char path[SYSFS_PATH_MAX];

	if (!dev) {
		errno = EINVAL;
		return -1;
	}

	memset(path, 0, SYSFS_PATH_MAX);
	memset(devpath, 0, SYSFS_PATH_MAX);
	safestrcpymax(path, dev->path, SYSFS_PATH_MAX);
	safestrcatmax(path, "/bus", SYSFS_PATH_MAX);
	if (!sysfs_path_is_link(path)) {
		if (!sysfs_get_link(path, devpath, SYSFS_PATH_MAX)) {
			if (sysfs_get_name_from_path(devpath, 
					dev->bus, SYSFS_NAME_LEN))
				return -1;
		}
		return 0;
	}
	return -1;
}

/**
 * sysfs_close_device_tree: closes every device in the supplied tree, 
 * 	closing children only.
 * @devroot: device root of tree.
 */
void sysfs_close_device_tree(struct sysfs_device *devroot)
{
	if (devroot) {
		if (devroot->children) {
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
 * sysfs_close_device: closes and cleans up a device
 * @dev = device to clean up
 */
void sysfs_close_device(struct sysfs_device *dev)
{
	if (dev) {
		if (dev->parent)
			sysfs_close_device(dev->parent);
		if (dev->children && dev->children->count)
			dlist_destroy(dev->children);
		if (dev->attrlist)
			dlist_destroy(dev->attrlist);
		free(dev);
	}
}

/**
 * alloc_device: allocates and initializes device structure
 * returns struct sysfs_device
 */
static struct sysfs_device *alloc_device(void)
{
	return (struct sysfs_device *) calloc(1, sizeof(struct sysfs_device));
}

/**
 * sysfs_open_device_path: opens and populates device structure
 * @path: path to device, this is the /sys/devices/ path
 * returns sysfs_device structure with success or NULL with error
 */
struct sysfs_device *sysfs_open_device_path(const char *path)
{
	struct sysfs_device *dev;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	if (sysfs_path_is_dir(path)) {
		dprintf("Incorrect path to device: %s\n", path);
		return NULL;
	}
	dev = alloc_device();
	if (!dev) {
		dprintf("Error allocating device at %s\n", path);
		return NULL;
	}
	if (sysfs_get_name_from_path(path, dev->bus_id, SYSFS_NAME_LEN)) {
		errno = EINVAL;
		dprintf("Error getting device bus_id\n");
		sysfs_close_device(dev);
		return NULL;
	}
	safestrcpy(dev->path, path);
	if (sysfs_remove_trailing_slash(dev->path)) {
		dprintf("Invalid path to device %s\n", dev->path);
		sysfs_close_device(dev);
		return NULL;
	}
	/*
	 * The "name" attribute no longer exists... return the device's
	 * sysfs representation instead, in the "dev->name" field, which
	 * implies that the dev->name and dev->bus_id contain same data.
	 */
	safestrcpy(dev->name, dev->bus_id);

	if (sysfs_get_device_bus(dev))
		dprintf("Could not get device bus\n");

	if (get_dev_driver(dev)) {
		dprintf("Could not get device %s's driver\n", dev->bus_id);
		safestrcpy(dev->driver_name, SYSFS_UNKNOWN);
	}

	return dev;
}

/**
 * sysfs_get_device_attr: searches dev's attributes by name
 * @dev: device to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference with success or NULL with error.
 */
struct sysfs_attribute *sysfs_get_device_attr(struct sysfs_device *dev,
						const char *name)
{
	if (!dev || !name) {
		errno = EINVAL;
		return NULL;
	}
	return get_attribute(dev, (char *)name);
}

/**
 * sysfs_get_device_attributes: gets list of device attributes
 * @dev: device whose attributes list is needed
 * returns dlist of attributes on success or NULL on error
 */
struct dlist *sysfs_get_device_attributes(struct sysfs_device *dev)
{
	if (!dev) {
		errno = EINVAL;
		return NULL;
	}
	return get_attributes_list(dev);
}

/**
 * get_device_absolute_path: looks up the bus the device is on, gets 
 * 		absolute path to the device
 * @device: device for which path is needed
 * @path: buffer to store absolute path
 * @psize: size of "path"
 * Returns 0 on success -1 on failure
 */
static int get_device_absolute_path(const char *device,	const char *bus, 
				char *path, size_t psize)
{
	char bus_path[SYSFS_PATH_MAX];

	if (!device || !path) {
		errno = EINVAL;
		return -1;
	}

	memset(bus_path, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(bus_path, SYSFS_PATH_MAX)) {
		dprintf ("Sysfs not supported on this system\n");
		return -1;
	}
	safestrcat(bus_path, "/");
	safestrcat(bus_path, SYSFS_BUS_NAME);
	safestrcat(bus_path, "/");
	safestrcat(bus_path, bus);
	safestrcat(bus_path, "/");
	safestrcat(bus_path, SYSFS_DEVICES_NAME);
	safestrcat(bus_path, "/");
	safestrcat(bus_path, device);
	/*
	 * We now are at /sys/bus/"bus_name"/devices/"device" which is a link.
	 * Now read this link to reach to the device.
	 */ 
	if (sysfs_get_link(bus_path, path, psize)) {
		dprintf("Error getting to device %s\n", device);
		return -1;
	}
	return 0;
}

/**
 * sysfs_open_device: open a device by id (use the "bus" subsystem)
 * @bus: bus the device belongs to
 * @bus_id: bus_id of the device to open - has to be the "bus_id" in 
 * 		/sys/bus/xxx/devices
 * returns struct sysfs_device if found, NULL otherwise
 * NOTE: 
 * 1. Use sysfs_close_device to close the device
 * 2. Bus the device is on must be supplied
 * 	Use sysfs_find_device_bus to get the bus name
 */
struct sysfs_device *sysfs_open_device(const char *bus,	const char *bus_id)
{
	char sysfs_path[SYSFS_PATH_MAX];
	struct sysfs_device *device;

	if (!bus_id || !bus) {
		errno = EINVAL;
		return NULL;
	}
	memset(sysfs_path, 0, SYSFS_PATH_MAX);
	if (get_device_absolute_path(bus_id, bus, sysfs_path, 
				SYSFS_PATH_MAX)) {
		dprintf("Error getting to device %s\n", bus_id);
		return NULL;
	}
	
	device = sysfs_open_device_path(sysfs_path);
	if (!device) {
		dprintf("Error opening device %s\n", bus_id);
		return NULL;
	}
	return device;
}

/**
 * sysfs_get_device_parent: opens up given device's parent and returns a 
 * 	reference to its sysfs_device
 * @dev: sysfs_device whose parent is requested
 * Returns sysfs_device of the parent on success and NULL on failure
 */
struct sysfs_device *sysfs_get_device_parent(struct sysfs_device *dev)
{
	char ppath[SYSFS_PATH_MAX], dpath[SYSFS_PATH_MAX], *tmp;

	if (!dev) {
		errno = EINVAL;
		return NULL;
	}

	if (dev->parent)
		return (dev->parent);

	memset(ppath, 0, SYSFS_PATH_MAX);
	memset(dpath, 0, SYSFS_PATH_MAX);
	safestrcpy(ppath, dev->path);
	tmp = strrchr(ppath, '/');
	if (!tmp) {
		dprintf("Invalid path to device %s\n", ppath);
		return NULL;
	}
	if (*(tmp + 1) == '\0') {
		*tmp = '\0';
		tmp = strrchr(tmp, '/');
		if (tmp == NULL) {
			dprintf("Invalid path to device %s\n", ppath);
			return NULL;
		}
	}
	*tmp = '\0';

	/* Make sure we're not at the top of the device tree */
	sysfs_get_mnt_path(dpath, SYSFS_PATH_MAX);
	safestrcat(dpath, "/" SYSFS_DEVICES_NAME);
	if (strcmp(dpath, ppath) == 0) {
		dprintf("Device at %s does not have a parent\n", dev->path);
		return NULL;
	}

	dev->parent = sysfs_open_device_path(ppath);
	if (!dev->parent) {
		dprintf("Error opening device %s's parent at %s\n", 
					dev->bus_id, ppath);
		return NULL;
	}
	return (dev->parent);
}
