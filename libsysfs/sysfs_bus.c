/*
 * sysfs_bus.c
 *
 * Generic bus utility functions for libsysfs
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

static void sysfs_close_dev(void *dev)
{
        sysfs_close_device((struct sysfs_device *)dev);
}

static void sysfs_close_drv(void *drv)
{
        sysfs_close_driver((struct sysfs_driver *)drv);
}

/*
 * compares devices' bus ids.
 * @a: device id looking for
 * @b: sysfs_device comparing being compared
 * returns 1 if a==b->bus_id or 0 not equal
 */
static int bus_device_id_equal(void *a, void *b)
{
	if (a == NULL || b == NULL)
		return 0;

	if (strcmp(((char *)a), ((struct sysfs_device *)b)->bus_id) 
	    == 0)
		return 1;
	return 0;
}

/*
 * compares drivers' names.
 * @a: driver name looking for
 * @b: sysfs_driver comparing being compared
 * returns 1 if a==b->name or 0 not equal
 */
static int bus_driver_name_equal(void *a, void *b)
{
	if (a == NULL || b == NULL)
		return 0;

	if (strcmp(((char *)a), ((struct sysfs_driver *)b)->name) == 0)
		return 1;
	return 0;
}

/**
 * sysfs_close_bus: close single bus
 * @bus: bus structure
 */
void sysfs_close_bus(struct sysfs_bus *bus)
{
	if (bus != NULL) {
		if (bus->directory != NULL)
			sysfs_close_directory(bus->directory);
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
	struct sysfs_device *bdev = NULL;
	struct sysfs_directory *devdir = NULL;
	struct sysfs_link *curl = NULL;
	char path[SYSFS_PATH_MAX];

	if (bus == NULL) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	safestrcpy(path, bus->path);
	safestrcat(path, "/");
	safestrcat(path, SYSFS_DEVICES_NAME);
	devdir = sysfs_open_directory(path);
	if (devdir == NULL) 
		return NULL;

	if (sysfs_read_dir_links(devdir) != 0) {
		sysfs_close_directory(devdir);
		return NULL;
	}

	if (devdir->links != NULL) {
		dlist_for_each_data(devdir->links, curl, struct sysfs_link) {
			bdev = sysfs_open_device_path(curl->target);
			if (bdev == NULL) {
				dprintf("Error opening device at %s\n",	
								curl->target);
				continue;
			}
			if (bus->devices == NULL)
				bus->devices = dlist_new_with_delete
					(sizeof(struct sysfs_device), 
					 		sysfs_close_dev);
			dlist_unshift_sorted(bus->devices, bdev, sort_list);
		}
	}
	sysfs_close_directory(devdir);

	return (bus->devices);
}

/**
 * sysfs_get_bus_drivers: get all pci drivers
 * @bus: pci bus to add drivers to
 * returns dlist of drivers with success and NULL with error
 */
struct dlist *sysfs_get_bus_drivers(struct sysfs_bus *bus)
{
	struct sysfs_driver *driver = NULL;
	struct sysfs_directory *drvdir = NULL;
	struct sysfs_directory *cursub = NULL;
	char path[SYSFS_PATH_MAX];

	if (bus == NULL) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	safestrcpy(path, bus->path);
	safestrcat(path, "/");
	safestrcat(path, SYSFS_DRIVERS_NAME);
	drvdir = sysfs_open_directory(path);
	if (drvdir == NULL) 
		return NULL;

	if (sysfs_read_dir_subdirs(drvdir) != 0) {
		sysfs_close_directory(drvdir);
		return NULL;
	}
	if (drvdir->subdirs != NULL) {
		dlist_for_each_data(drvdir->subdirs, cursub, 
						struct sysfs_directory) {
			driver = sysfs_open_driver_path(cursub->path);
			if (driver == NULL) {
				dprintf("Error opening driver at %s\n",	
								cursub->path);
				continue;
			}
			if (bus->drivers == NULL)
				bus->drivers = dlist_new_with_delete
					(sizeof(struct sysfs_driver), 
					 		sysfs_close_drv);
			dlist_unshift_sorted(bus->drivers, driver, sort_list);
		}
	}
	sysfs_close_directory(drvdir);
	return (bus->drivers);
}

/**
 * sysfs_open_bus: opens specific bus and all its devices on system
 * returns sysfs_bus structure with success or NULL with error.
 */
struct sysfs_bus *sysfs_open_bus(const char *name)
{
	struct sysfs_bus *bus = NULL;
	char buspath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(buspath, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_mnt_path(buspath, SYSFS_PATH_MAX)) != 0) {
		dprintf("Sysfs not supported on this system\n");
		return NULL;
	}

	safestrcat(buspath, "/");
	safestrcat(buspath, SYSFS_BUS_NAME);
	safestrcat(buspath, "/");
	safestrcat(buspath, name);
	if ((sysfs_path_is_dir(buspath)) != 0) {
		dprintf("Invalid path to bus: %s\n", buspath);
		return NULL;
	}
	bus = alloc_bus();
	if (bus == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	safestrcpy(bus->name, name);	
	safestrcpy(bus->path, buspath);
	if ((sysfs_remove_trailing_slash(bus->path)) != 0) {
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
struct sysfs_device *sysfs_get_bus_device(struct sysfs_bus *bus, char *id)
{
	if (bus == NULL || id == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (bus->devices == NULL) {
		bus->devices = sysfs_get_bus_devices(bus);
		if (bus->devices == NULL)
			return NULL;
	}
		
	return (struct sysfs_device *)dlist_find_custom(bus->devices, id,
		bus_device_id_equal);
}

/**
 * sysfs_get_bus_driver: Get specific driver on bus using driver name
 * @bus: bus to find driver on
 * @drvname: name of driver
 * returns struct sysfs_driver reference or NULL if not found.
 */
struct sysfs_driver *sysfs_get_bus_driver(struct sysfs_bus *bus, 
							char *drvname)
{
	if (bus == NULL || drvname == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (bus->drivers == NULL) {
		bus->drivers = sysfs_get_bus_drivers(bus);
		if (bus->drivers == NULL)
			return NULL;
	}
	
	return (struct sysfs_driver *)dlist_find_custom(bus->drivers, drvname,
		bus_driver_name_equal);
}

/**
 * sysfs_get_bus_attributes: returns bus' dlist of attributes
 * @bus: bus to get attributes for.
 * returns dlist of attributes or NULL if there aren't any.
 */
struct dlist *sysfs_get_bus_attributes(struct sysfs_bus *bus)
{
	if (bus == NULL)
		return NULL;

	if (bus->directory == NULL) {
		bus->directory = sysfs_open_directory(bus->path);
		if (bus->directory == NULL)
			return NULL;
	}
	if (bus->directory->attributes == NULL) {
		if ((sysfs_read_dir_attributes(bus->directory)) != 0) 
			return NULL;
	}
	return bus->directory->attributes;
}

/**
 * sysfs_refresh_bus_attributes: refreshes the bus's list of attributes
 * @bus: sysfs_bus whose attributes to refresh
 * 
 * NOTE: Upon return, prior references to sysfs_attributes for this bus
 * 		_may_ not be valid
 * 
 * Returns list of attributes on success and NULL on failure
 */
struct dlist *sysfs_refresh_bus_attributes(struct sysfs_bus *bus)
{
	if (bus == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (bus->directory == NULL)
		return (sysfs_get_bus_attributes(bus));
	
	if ((sysfs_refresh_dir_attributes(bus->directory)) != 0) {
		dprintf("Error refreshing bus attributes\n");
		return NULL;
	}

	return (bus->directory->attributes);
}

/**
 * sysfs_get_bus_attribute: gets a specific bus attribute, if buses had
 * 	attributes.
 * @bus: bus to retrieve attribute from
 * @attrname: attribute name to retrieve
 * returns reference to sysfs_attribute if found or NULL if not found
 */
struct sysfs_attribute *sysfs_get_bus_attribute(struct sysfs_bus *bus,
						char *attrname)
{
	struct dlist *attrlist = NULL;
	
	if (bus == NULL) {
		errno = EINVAL;
		return NULL;
	}
	attrlist = sysfs_get_bus_attributes(bus);
	if (attrlist == NULL)
		return NULL;
	
	return sysfs_get_directory_attribute(bus->directory, attrname);
}

/**
 * sysfs_find_driver_bus: locates the bus the driver is on.
 * @driver: name of the driver to locate
 * @busname: buffer to copy name to
 * @bsize: buffer size
 * returns 0 with success, -1 with error
 */
int sysfs_find_driver_bus(const char *driver, char *busname, size_t bsize)
{
	char subsys[SYSFS_PATH_MAX], *bus = NULL, *curdrv = NULL;
	struct dlist *buslist = NULL, *drivers = NULL;

	if (driver == NULL || busname == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(subsys, 0, SYSFS_PATH_MAX);
	safestrcpy(subsys, SYSFS_BUS_NAME);
	buslist = sysfs_open_subsystem_list(subsys);
	if (buslist != NULL) {
		dlist_for_each_data(buslist, bus, char) {
			memset(subsys, 0, SYSFS_PATH_MAX);
			safestrcpy(subsys, SYSFS_BUS_NAME);
			safestrcat(subsys, "/");
			safestrcat(subsys, bus);
			safestrcat(subsys, "/");
			safestrcat(subsys, SYSFS_DRIVERS_NAME);
			drivers = sysfs_open_subsystem_list(subsys);
			if (drivers != NULL) {
				dlist_for_each_data(drivers, curdrv, char) {
					if (strcmp(driver, curdrv) == 0) {
						safestrcpymax(busname, 
								bus, bsize);
						sysfs_close_list(drivers);
						sysfs_close_list(buslist);
						return 0;
					}
				}
				sysfs_close_list(drivers);
			}
		}
		sysfs_close_list(buslist);
	}
	return -1;
}
