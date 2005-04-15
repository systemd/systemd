/*
 * sysfs_bus.c
 *
 * Generic bus utility functions for libsysfs
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

static void sysfs_close_dev(void *dev)
{
        sysfs_close_device((struct sysfs_device *)dev);
}

static void sysfs_close_drv(void *drv)
{
        sysfs_close_driver((struct sysfs_driver *)drv);
}

/*
 * compares names.
 * @a: name looked for
 * @b: sysfs_device comparing being compared
 * returns 1 if a==b->name or 0 not equal
 */
static int name_equal(void *a, void *b)
{
	if (!a || !b)
		return 0;

	if (strcmp(((char *)a), ((struct sysfs_device *)b)->name) == 0)
		return 1;

	return 0;
}

/**
 * sysfs_close_bus: close single bus
 * @bus: bus structure
 */
void sysfs_close_bus(struct sysfs_bus *bus)
{
	if (bus) {
		if (bus->attrlist)
			dlist_destroy(bus->attrlist);
		if (bus->devices)
			dlist_destroy(bus->devices);
		if (bus->drivers)
			dlist_destroy(bus->drivers);
		free(bus);
	}
}

/**
 * alloc_bus: mallocs new bus structure
 * returns sysfs_bus_bus struct or NULL
 */
static struct sysfs_bus *alloc_bus(void)
{
	return (struct sysfs_bus *)calloc(1, sizeof(struct sysfs_bus));
}

/**
 * sysfs_get_bus_devices: gets all devices for bus
 * @bus: bus to get devices for
 * returns dlist of devices with success and NULL with failure
 */
struct dlist *sysfs_get_bus_devices(struct sysfs_bus *bus)
{
	struct sysfs_device *dev;
	struct dlist *linklist;
	char path[SYSFS_PATH_MAX], devpath[SYSFS_PATH_MAX];
	char target[SYSFS_PATH_MAX];
	char *curlink;

	if (!bus) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	safestrcpy(path, bus->path);
	safestrcat(path, "/");
	safestrcat(path, SYSFS_DEVICES_NAME);

	linklist = read_dir_links(path);
	if (linklist) {
		dlist_for_each_data(linklist, curlink, char) {
			if (bus->devices) {
				dev = (struct sysfs_device *)
					dlist_find_custom(bus->devices,
					(void *)curlink, name_equal);
				if (dev)
					continue;
			}
			safestrcpy(devpath, path);
			safestrcat(devpath, "/");
			safestrcat(devpath, curlink);
			if (sysfs_get_link(devpath, target, SYSFS_PATH_MAX)) {
				dprintf("Error getting link - %s\n", devpath);
				continue;
			}
			dev = sysfs_open_device_path(target);
			if (!dev) {
				dprintf("Error opening device at %s\n",	
								target);
				continue;
			}
			if (!bus->devices)
				bus->devices = dlist_new_with_delete
					(sizeof(struct sysfs_device), 
					 		sysfs_close_dev);
			dlist_unshift_sorted(bus->devices, dev, sort_list);
		}
		sysfs_close_list(linklist);
	}
	return (bus->devices);
}

/**
 * sysfs_get_bus_drivers: gets all drivers for bus
 * @bus: bus to get devices for
 * returns dlist of devices with success and NULL with failure
 */
struct dlist *sysfs_get_bus_drivers(struct sysfs_bus *bus)
{
	struct sysfs_driver *drv;
	struct dlist *dirlist;
	char path[SYSFS_PATH_MAX], drvpath[SYSFS_PATH_MAX];
	char *curdir;

	if (!bus) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	safestrcpy(path, bus->path);
	safestrcat(path, "/");
	safestrcat(path, SYSFS_DRIVERS_NAME);

	dirlist = read_dir_subdirs(path);
	if (dirlist) {
		dlist_for_each_data(dirlist, curdir, char) {
			if (bus->drivers) {
				drv = (struct sysfs_driver *)
					dlist_find_custom(bus->drivers,
					(void *)curdir, name_equal);
				if (drv)
					continue;
			}
			safestrcpy(drvpath, path);
			safestrcat(drvpath, "/");
			safestrcat(drvpath, curdir);
			drv = sysfs_open_driver_path(drvpath);
			if (!drv) {
				dprintf("Error opening driver at %s\n",	
								drvpath);
				continue;
			}
			if (!bus->drivers)
				bus->drivers = dlist_new_with_delete
					(sizeof(struct sysfs_driver), 
					 		sysfs_close_drv);
			dlist_unshift_sorted(bus->drivers, drv, sort_list);
		}
		sysfs_close_list(dirlist);
	}
	return (bus->drivers);
}

/**
 * sysfs_open_bus: opens specific bus and all its devices on system
 * returns sysfs_bus structure with success or NULL with error.
 */
struct sysfs_bus *sysfs_open_bus(const char *name)
{
	struct sysfs_bus *bus;
	char buspath[SYSFS_PATH_MAX];

	if (!name) {
		errno = EINVAL;
		return NULL;
	}

	memset(buspath, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(buspath, SYSFS_PATH_MAX)) {
		dprintf("Sysfs not supported on this system\n");
		return NULL;
	}

	safestrcat(buspath, "/");
	safestrcat(buspath, SYSFS_BUS_NAME);
	safestrcat(buspath, "/");
	safestrcat(buspath, name);
	if (sysfs_path_is_dir(buspath)) {
		dprintf("Invalid path to bus: %s\n", buspath);
		return NULL;
	}
	bus = alloc_bus();
	if (!bus) {
		dprintf("calloc failed\n");
		return NULL;
	}
	safestrcpy(bus->name, name);	
	safestrcpy(bus->path, buspath);
	if (sysfs_remove_trailing_slash(bus->path)) {
		dprintf("Incorrect path to bus %s\n", bus->path);
		sysfs_close_bus(bus);
		return NULL;
	}

	return bus;
}

/**
 * sysfs_get_bus_device: Get specific device on bus using device's id
 * @bus: bus to find device on
 * @id: bus_id for device
 * returns struct sysfs_device reference or NULL if not found.
 */
struct sysfs_device *sysfs_get_bus_device(struct sysfs_bus *bus, 
		const char *id)
{
	struct sysfs_device *dev = NULL;
	char devpath[SYSFS_PATH_MAX], target[SYSFS_PATH_MAX];
	
	if (!bus || !id) {
		errno = EINVAL;
		return NULL;
	}

	if (bus->devices) {
		dev = (struct sysfs_device *)dlist_find_custom
			(bus->devices, (void *)id, name_equal);
		if (dev)
			return dev;
	}
	safestrcpy(devpath, bus->path);
	safestrcat(devpath, "/");
	safestrcat(devpath, SYSFS_DEVICES_NAME);
	safestrcat(devpath, "/");
	safestrcat(devpath, id);
	if (sysfs_path_is_link(devpath)) {
		dprintf("No such device %s on bus %s?\n", id, bus->name);
		return NULL;
	}
	if (!sysfs_get_link(devpath, target, SYSFS_PATH_MAX)) {
		dev = sysfs_open_device_path(target);
		if (!dev) {
			dprintf("Error opening device at %s\n", target);
			return NULL;
		}
		if (!bus->devices)
			bus->devices = dlist_new_with_delete
					(sizeof(struct sysfs_device), 
					 		sysfs_close_dev);
		dlist_unshift_sorted(bus->devices, dev, sort_list);
	}
	return dev;
}

/**
 * sysfs_get_bus_driver: Get specific driver on bus using driver name
 * @bus: bus to find driver on
 * @drvname: name of driver
 * returns struct sysfs_driver reference or NULL if not found.
 */
struct sysfs_driver *sysfs_get_bus_driver(struct sysfs_bus *bus,
		const char *drvname)
{
	struct sysfs_driver *drv;
	char drvpath[SYSFS_PATH_MAX];
	
	if (!bus || !drvname) {
		errno = EINVAL;
		return NULL;
	}

	if (bus->drivers) {
		drv = (struct sysfs_driver *)dlist_find_custom
			(bus->drivers, (void *)drvname, name_equal);
		if (drv)
			return drv;
	}
	safestrcpy(drvpath, bus->path);
	safestrcat(drvpath, "/");
	safestrcat(drvpath, SYSFS_DRIVERS_NAME);
	safestrcat(drvpath, "/");
	safestrcat(drvpath, drvname);
	drv = sysfs_open_driver_path(drvpath);
	if (!drv) {
		dprintf("Error opening driver at %s\n", drvpath);
		return NULL;
	}
	if (!bus->drivers)
		bus->drivers = dlist_new_with_delete
				(sizeof(struct sysfs_driver), 
				 		sysfs_close_drv);
	dlist_unshift_sorted(bus->drivers, drv, sort_list);
	return drv;
}

