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
#include "sysfs/libsysfs.h"
#include "sysfs.h"

/**
 * get_dev_driver: fills in the dev->driver_name field 
 *
 * Returns 0 on SUCCESS and 1 on error
 */
static int get_dev_driver(struct sysfs_device *dev)
{
	struct dlist *drvlist = NULL;
	char path[SYSFS_PATH_MAX], devpath[SYSFS_PATH_MAX];
	char *drv = NULL, *c = NULL;
	
	if (dev == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (dev->bus[0] == '\0')
		return 1;
	memset(path, 0, SYSFS_PATH_MAX);
	memset(devpath, 0, SYSFS_PATH_MAX);
	safestrcpy(path, SYSFS_BUS_NAME);
	safestrcat(path, "/");
	safestrcat(path, dev->bus);
	safestrcat(path, "/");
	safestrcat(path, SYSFS_DRIVERS_NAME);

	safestrcpy(devpath, dev->path);
	c = strstr(devpath, SYSFS_DEVICES_NAME);
	if (c == NULL)
		return 1;
	*c = '\0';
	safestrcatmax(c, path, (sizeof(devpath) - strlen(devpath)));

	drvlist = sysfs_open_subsystem_list(path);
	if (drvlist != NULL) {
		dlist_for_each_data(drvlist, drv, char) {
			safestrcpy(path, devpath);
			safestrcat(path, "/");
			safestrcat(path, drv);
			safestrcat(path, "/");
			safestrcat(path, dev->bus_id);
			if (sysfs_path_is_link(path) == 0) {
				safestrcpy(dev->driver_name, drv);
				sysfs_close_list(drvlist);
				return 0;
			}
		}
		sysfs_close_list(drvlist);
	}
	return 1;
}
	
/**
 * sysfs_get_device_bus: retrieves the bus name the device is on, checks path 
 * 	to bus' link to make sure it has correct device.
 * @dev: device to get busname.
 * returns 0 with success and -1 with error.
 */
int sysfs_get_device_bus(struct sysfs_device *dev)
{
	char subsys[SYSFS_NAME_LEN], path[SYSFS_PATH_MAX];
	char target[SYSFS_PATH_MAX], *bus = NULL, *c = NULL;
	struct dlist *buslist = NULL;

	if (dev == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(subsys, 0, SYSFS_NAME_LEN);
	safestrcpy(subsys, SYSFS_BUS_NAME);  /* subsys = bus */
	buslist = sysfs_open_subsystem_list(subsys);
	if (buslist != NULL) {
		dlist_for_each_data(buslist, bus, char) {
			memset(path, 0, SYSFS_PATH_MAX);
			safestrcpy(path, dev->path);
			c = strstr(path, "/devices");
			if (c == NULL) {
				dprintf("Invalid path to device %s\n", path);
				sysfs_close_list(buslist);
				return -1;
			}
			*c = '\0';
			safestrcat(path, "/");
			safestrcat(path, SYSFS_BUS_NAME);
			safestrcat(path, "/");
			safestrcat(path, bus);
			safestrcat(path, "/");
			safestrcat(path, SYSFS_DEVICES_NAME);
			safestrcat(path, "/");
			safestrcat(path, dev->bus_id);
			if ((sysfs_path_is_link(path)) == 0) {
				memset(target, 0, SYSFS_PATH_MAX);
				if ((sysfs_get_link(path, target, 
						SYSFS_PATH_MAX)) != 0) {
					dprintf("Error getting link target\n");
					sysfs_close_list(buslist);
					return -1;
				}
				if (!(strncmp(target, dev->path, 
							SYSFS_PATH_MAX))) {
					safestrcpy(dev->bus, bus);
					sysfs_close_list(buslist);
					return 0;
				}
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
void sysfs_close_device_tree(struct sysfs_device *devroot)
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
		if (dev->parent != NULL)
			sysfs_close_device(dev->parent);
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
 * open_device_dir: opens up sysfs_directory for specific root dev
 * @name: name of root
 * returns struct sysfs_directory with success and NULL with error
 */
static struct sysfs_directory *open_device_dir(const char *path)
{
	struct sysfs_directory *rdir = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}

	rdir = sysfs_open_directory(path);
	if (rdir == NULL) {
		errno = EINVAL;
		dprintf ("Device %s not supported on this system\n", path);
		return NULL;
	}
	if ((sysfs_read_dir_subdirs(rdir)) != 0) {
		dprintf ("Error reading device at dir %s\n", path);
		sysfs_close_directory(rdir);
		return NULL;
	}
	
	return rdir;
}

/**
 * sysfs_open_device_path: opens and populates device structure
 * @path: path to device, this is the /sys/devices/ path
 * returns sysfs_device structure with success or NULL with error
 */
struct sysfs_device *sysfs_open_device_path(const char *path)
{
	struct sysfs_device *dev = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((sysfs_path_is_dir(path)) != 0) {
		dprintf("Incorrect path to device: %s\n", path);
		return NULL;
	}
	dev = alloc_device();	
	if (dev == NULL) {
		dprintf("Error allocating device at %s\n", path);
		return NULL;
	}
	if ((sysfs_get_name_from_path(path, dev->bus_id, 
					SYSFS_NAME_LEN)) != 0) {
		errno = EINVAL;
		dprintf("Error getting device bus_id\n");
		sysfs_close_device(dev);
		return NULL;
	}
	safestrcpy(dev->path, path);
	if ((sysfs_remove_trailing_slash(dev->path)) != 0) {
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
	
	if (sysfs_get_device_bus(dev) != 0)
		dprintf("Could not get device bus\n");
	
	if (get_dev_driver(dev) != 0) {
		dprintf("Could not get device %s's driver\n", dev->bus_id);
		safestrcpy(dev->driver_name, SYSFS_UNKNOWN);
	}

	return dev;
}

/**
 * sysfs_open_device_tree: opens root device and all of its children,
 *	creating a tree of devices. Only opens children.
 * @path: sysfs path to devices
 * returns struct sysfs_device and its children with success or NULL with
 *	error.
 */
struct sysfs_device *sysfs_open_device_tree(const char *path)
{
	struct sysfs_device *rootdev = NULL, *new = NULL;
	struct sysfs_directory *cur = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	rootdev = sysfs_open_device_path(path);
	if (rootdev == NULL) {
		dprintf("Error opening root device at %s\n", path);
		return NULL;
	}
	if (rootdev->directory == NULL) {
		rootdev->directory = open_device_dir(rootdev->path);
		if (rootdev->directory == NULL) 
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
					sysfs_close_dev_tree);
			dlist_unshift_sorted(rootdev->children, 
							new, sort_list);
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
 * sysfs_get_root_devices: opens up all the devices under this root device
 * @root: root device to open devices for
 * returns dlist of devices with success and NULL with error
 */
struct dlist *sysfs_get_root_devices(struct sysfs_root_device *root)
{
	struct sysfs_device *dev = NULL;
	struct sysfs_directory *cur = NULL;

	if (root == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (root->directory == NULL) {
		root->directory = open_device_dir(root->path);
		if (root->directory == NULL)
			return NULL;
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
		dlist_unshift_sorted(root->devices, dev, sort_list);
	}

	return root->devices;
}

/**
 * sysfs_open_root_device: opens sysfs devices root and all of its
 *	devices.
 * @name: name of /sys/devices/root to open
 * returns struct sysfs_root_device if success and NULL with error
 */
struct sysfs_root_device *sysfs_open_root_device(const char *name)
{
	struct sysfs_root_device *root = NULL;
	char rootpath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(rootpath, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(rootpath, SYSFS_PATH_MAX) != 0) {
		dprintf ("Sysfs not supported on this system\n");
		return NULL;
	}

	safestrcat(rootpath, "/");
	safestrcat(rootpath, SYSFS_DEVICES_NAME);
	safestrcat(rootpath, "/");
	safestrcat(rootpath, name);
	if ((sysfs_path_is_dir(rootpath)) != 0) {
		errno = EINVAL;
		dprintf("Invalid root device: %s\n", name);
		return NULL;
	}
	root = (struct sysfs_root_device *)calloc
					(1, sizeof(struct sysfs_root_device));
	if (root == NULL) {
		dprintf("calloc failure\n");
		return NULL;
	}
	safestrcpy(root->name, name);
	safestrcpy(root->path, rootpath);
	if ((sysfs_remove_trailing_slash(root->path)) != 0) {
		dprintf("Invalid path to root device %s\n", root->path);
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
	if (device == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (device->directory == NULL) {
		device->directory = sysfs_open_directory(device->path);
		if (device->directory == NULL) 
			return NULL;
	}
	if (device->directory->attributes == NULL) {
		if ((sysfs_read_dir_attributes(device->directory)) != 0)
			return NULL;
	}
	return (device->directory->attributes);
}

/**
 * sysfs_refresh_device_attributes: refreshes the device's list of attributes
 * @device: sysfs_device whose attributes to refresh
 *  
 * NOTE: Upon return, prior references to sysfs_attributes for this device
 * 		_may_ not be valid
 *
 * Returns list of attributes on success and NULL on failure
 */
struct dlist *sysfs_refresh_device_attributes(struct sysfs_device *device)
{
	if (device == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (device->directory == NULL)
		return (sysfs_get_device_attributes(device));

	if ((sysfs_refresh_dir_attributes(device->directory)) != 0) {
		dprintf("Error refreshing device attributes\n");
		return NULL;
	}

	return (device->directory->attributes);
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
	struct dlist *attrlist = NULL;

	if (dev == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}
	
	attrlist = sysfs_get_device_attributes(dev);
	if (attrlist == NULL)
		return NULL;

	return sysfs_get_directory_attribute(dev->directory, (char *)name);
}

/**
 * get_device_absolute_path: looks up the bus the device is on, gets 
 * 		absolute path to the device
 * @device: device for which path is needed
 * @path: buffer to store absolute path
 * @psize: size of "path"
 * Returns 0 on success -1 on failure
 */
static int get_device_absolute_path(const char *device, const char *bus, 
				char *path, size_t psize)
{
	char bus_path[SYSFS_PATH_MAX];

	if (device == NULL || path == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(bus_path, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(bus_path, SYSFS_PATH_MAX) != 0) {
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
	if ((sysfs_get_link(bus_path, path, psize)) != 0) {
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
struct sysfs_device *sysfs_open_device(const char *bus, const char *bus_id)
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
	
	device = sysfs_open_device_path(sysfs_path);
	if (device == NULL) {
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
	char ppath[SYSFS_PATH_MAX], *tmp = NULL;

	if (dev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (dev->parent != NULL)
		return (dev->parent);

	memset(ppath, 0, SYSFS_PATH_MAX);
	safestrcpy(ppath, dev->path);
	tmp = strrchr(ppath, '/');
	if (tmp == NULL) {
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
	
	/*
	 * All "devices" have the "detach_state" attribute - validate here
	 */
	safestrcat(ppath, "/detach_state");
	if ((sysfs_path_is_file(ppath)) != 0) {
		dprintf("Device at %s does not have a parent\n", dev->path);
		return NULL;
	}
	tmp = strrchr(ppath, '/');
	*tmp = '\0';
	dev->parent = sysfs_open_device_path(ppath);
	if (dev->parent == NULL) {
		dprintf("Error opening device %s's parent at %s\n", 
					dev->bus_id, ppath);
		return NULL;
	}
	return (dev->parent);
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
struct sysfs_attribute *sysfs_open_device_attr(const char *bus,
		const char *bus_id, const char *attrib)
{
	struct sysfs_attribute *attribute = NULL;
	char devpath[SYSFS_PATH_MAX];
	
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
	safestrcat(devpath, "/");
	safestrcat(devpath, attrib);
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

