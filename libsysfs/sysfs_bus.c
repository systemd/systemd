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

	if (strcmp(((unsigned char *)a), ((struct sysfs_device *)b)->bus_id) 
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

	if (strcmp(((unsigned char *)a), ((struct sysfs_driver *)b)->name) == 0)
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
 * open_bus_dir: opens up sysfs bus directory
 * returns sysfs_directory struct with success and NULL with error
 */
static struct sysfs_directory *open_bus_dir(const unsigned char *name)
{
	struct sysfs_directory *busdir = NULL;
	unsigned char buspath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(buspath, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_mnt_path(buspath, SYSFS_PATH_MAX)) != 0) {
		dprintf("Sysfs not supported on this system\n");
		return NULL;
	}

	if (sysfs_trailing_slash(buspath) == 0)
		strcat(buspath, "/");
		
	strcat(buspath, SYSFS_BUS_NAME);
	strcat(buspath, "/");
	strcat(buspath, name);
	busdir = sysfs_open_directory(buspath);
	if (busdir == NULL) {
		errno = EINVAL;
		dprintf("Bus %s not supported on this system\n",
			name);
		return NULL;
	}
	if ((sysfs_read_directory(busdir)) != 0) {
		dprintf("Error reading %s bus dir %s\n", name, 
			buspath);
		sysfs_close_directory(busdir);
		return NULL;
	}
	/* read in devices and drivers subdirs */
	sysfs_read_all_subdirs(busdir);

	return busdir;
}

/**
 * get_all_bus_devices: gets all devices for bus
 * @bus: bus to get devices for
 * returns 0 with success and -1 with failure
 */
static int get_all_bus_devices(struct sysfs_bus *bus)
{
	struct sysfs_device *bdev = NULL;
	struct sysfs_directory *cur = NULL;
	struct sysfs_link *curl = NULL;

	if (bus == NULL || bus->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (bus->directory->subdirs == NULL)
		return 0;

	dlist_for_each_data(bus->directory->subdirs, cur, 
			struct sysfs_directory) {
		if (strcmp(cur->name, SYSFS_DEVICES_NAME) != 0)
			continue;
		if (cur->links == NULL)
			continue;
		dlist_for_each_data(cur->links, curl, struct sysfs_link) {
			bdev = sysfs_open_device(curl->target);
			if (bdev == NULL) {
				dprintf("Error opening device at %s\n",
					curl->target);
				continue;
			}
                        if (bus->devices == NULL)
				bus->devices = dlist_new_with_delete
					(sizeof(struct sysfs_device),
						 	sysfs_close_dev);
			dlist_unshift(bus->devices, bdev);
		}
	}
			
	return 0;
}

/**
 * get_all_bus_drivers: get all pci drivers
 * @bus: pci bus to add drivers to
 * returns 0 with success and -1 with error
 */
static int get_all_bus_drivers(struct sysfs_bus *bus)
{
	struct sysfs_driver *driver = NULL;
	struct sysfs_directory *cur = NULL;
	struct sysfs_directory *cursub = NULL;

	if (bus == NULL || bus->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (bus->directory->subdirs == NULL)
		return 0;

	dlist_for_each_data(bus->directory->subdirs, cur,
			struct sysfs_directory) {
		if (strcmp(cur->name, SYSFS_DRIVERS_NAME) != 0)
			continue;
		if (cur->subdirs == NULL)
			continue;
		dlist_for_each_data(cur->subdirs, cursub,
				struct sysfs_directory) {
			driver = sysfs_open_driver(cursub->path);
			if (driver == NULL) {
				dprintf("Error opening driver at %s\n",
					cursub->path);
				continue;
			}
                        if (bus->drivers == NULL)
				bus->drivers = dlist_new_with_delete
					(sizeof(struct sysfs_driver),
					 		sysfs_close_drv);
			dlist_unshift(bus->drivers, driver);
		}
	}
	
	return 0;
}

/**
 * match_bus_device_to_driver: returns 1 if device is bound to driver
 * @driver: driver to match
 * @busid: busid of device to match
 * returns 1 if found and 0 if not found
 */
static int match_bus_device_to_driver(struct sysfs_driver *driver, 
							unsigned char *busid)
{
	struct sysfs_link *cur = NULL;
	int found = 0;

	if (driver == NULL || driver->directory == NULL || busid == NULL) {
		errno = EINVAL;
		return found;
	}
	if (driver->directory->links != NULL) {
		dlist_for_each_data(driver->directory->links, cur,
				struct sysfs_link) {
			if ((strcmp(cur->name, busid)) == 0)
				found++;
		}
	}
	return found;
}

/**
 * link_bus_devices_to_drivers: goes through and links devices to drivers
 * @bus: bus to link
 */
static void link_bus_devices_to_drivers(struct sysfs_bus *bus)
{
	struct sysfs_device *dev = NULL;
	struct sysfs_driver *drv = NULL;
	
	if (bus != NULL && bus->devices != NULL && bus->drivers != NULL) {
		dlist_for_each_data(bus->devices, dev, struct sysfs_device) {
			dlist_for_each_data(bus->drivers, drv,
					struct sysfs_driver) {
				if ((match_bus_device_to_driver(drv, 
						dev->bus_id)) != 0) {
					strncpy(dev->driver_name, drv->name,
							SYSFS_NAME_LEN);
					if (drv->devices == NULL)
						drv->devices = dlist_new
							(sizeof(struct 
								sysfs_device));
					dlist_unshift(drv->devices, dev);
				}
			}
		}
	}
}

/**
 * sysfs_open_bus: opens specific bus and all its devices on system
 * returns sysfs_bus structure with success or NULL with error.
 */
struct sysfs_bus *sysfs_open_bus(const unsigned char *name)
{
	struct sysfs_bus *bus = NULL;
	struct sysfs_directory *busdir = NULL;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	bus = alloc_bus();
	if (bus == NULL) {
		dprintf("calloc failed\n");
		return NULL;
	}
	strcpy(bus->name, name);	
	busdir = open_bus_dir(name);
	if (busdir == NULL) {
		dprintf("Invalid bus, %s not supported on this system\n",
			name);
		sysfs_close_bus(bus);
		return NULL;
	}
	strcpy(bus->path, busdir->path);
	bus->directory = busdir;
	if ((get_all_bus_devices(bus)) != 0) {
		dprintf("Error reading %s bus devices\n", name);
		sysfs_close_bus(bus);
		return NULL;
	}
	if ((get_all_bus_drivers(bus)) != 0) {
		dprintf("Error reading %s bus drivers\n", name);
		sysfs_close_bus(bus);
		return NULL;
	}
	link_bus_devices_to_drivers(bus);

	return bus;
}

/**
 * sysfs_get_bus_device: Get specific device on bus using device's id
 * @bus: bus to find device on
 * @id: bus_id for device
 * returns struct sysfs_device reference or NULL if not found.
 */
struct sysfs_device *sysfs_get_bus_device(struct sysfs_bus *bus, 
							unsigned char *id)
{
	if (bus == NULL || id == NULL) {
		errno = EINVAL;
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
							unsigned char *drvname)
{
	if (bus == NULL || drvname == NULL) {
		errno = EINVAL;
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
	if (bus == NULL || bus->directory == NULL)
		return NULL;
	return bus->directory->attributes;
}

/**
 * sysfs_get_bus_attribute: gets a specific bus attribute, if buses had
 * 	attributes.
 * @bus: bus to retrieve attribute from
 * @attrname: attribute name to retrieve
 * returns reference to sysfs_attribute if found or NULL if not found
 */
struct sysfs_attribute *sysfs_get_bus_attribute(struct sysfs_bus *bus,
						unsigned char *attrname)
{
	if (bus == NULL || bus->directory == NULL || attrname == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return sysfs_get_directory_attribute(bus->directory, attrname);
}

/**
 * sysfs_open_bus_device: locates a device on a bus and returns it. Device
 * 	must be closed using sysfs_close_device.
 * @busname: Name of bus to search
 * @dev_id: Id of device on bus.
 * returns sysfs_device if found or NULL if not.
 */
struct sysfs_device *sysfs_open_bus_device(unsigned char *busname, 
							unsigned char *dev_id)
{
	struct sysfs_device *rdev = NULL;
	char path[SYSFS_PATH_MAX];

	if (busname == NULL || dev_id == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(path, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount point\n");
		return NULL;
	}

	if (sysfs_trailing_slash(path) == 0)
		strcat(path, "/");
	strcat(path, SYSFS_BUS_NAME);
	strcat(path, "/");
	strcat(path, busname);
	strcat(path, "/");
	strcat(path, SYSFS_DEVICES_NAME);
	strcat(path, "/");
	strcat(path, dev_id);

	rdev = sysfs_open_device(path);
	if (rdev == NULL) {
		dprintf("Error getting device %s on bus %s\n",
				dev_id, busname);
		return NULL;
	}
	
	return rdev;
}

/**
 * sysfs_find_driver_bus: locates the bus the driver is on.
 * @driver: name of the driver to locate
 * @busname: buffer to copy name to
 * @bsize: buffer size
 * returns 0 with success, -1 with error
 */
int sysfs_find_driver_bus(const unsigned char *driver, unsigned char *busname,
							size_t bsize)
{
	unsigned char subsys[SYSFS_PATH_MAX], *bus = NULL, *curdrv = NULL;
	struct dlist *buslist = NULL, *drivers = NULL;

	if (driver == NULL || busname == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(subsys, 0, SYSFS_PATH_MAX);
	strcpy(subsys, SYSFS_BUS_NAME);
	buslist = sysfs_open_subsystem_list(subsys);
	if (buslist != NULL) {
		dlist_for_each_data(buslist, bus, char) {
			memset(subsys, 0, SYSFS_PATH_MAX);
			strcat(subsys, "/");
			strcpy(subsys, SYSFS_BUS_NAME);
			strcat(subsys, "/");
			strcat(subsys, bus);
			strcat(subsys, "/");
			strcat(subsys, SYSFS_DRIVERS_NAME);
			drivers = sysfs_open_subsystem_list(subsys);
			if (drivers != NULL) {
				dlist_for_each_data(drivers, curdrv, char) {
					if (strcmp(driver, curdrv) == 0) {
						strncpy(busname, bus, bsize);
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
					
