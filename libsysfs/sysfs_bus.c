/*
 * sysfs_bus.c
 *
 * Generic bus utility functions for libsysfs
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
 * sysfs_close_bus: close single bus
 * @bus: bus structure
 */
void sysfs_close_bus(struct sysfs_bus *bus)
{
	struct sysfs_device *curdev = NULL, *nextdev = NULL;
	struct sysfs_driver *curdrv = NULL, *nextdrv = NULL;

	if (bus != NULL) {
		if (bus->directory != NULL)
			sysfs_close_directory(bus->directory);
		for (curdev = bus->devices; curdev != NULL;
		     curdev = nextdev) {
			nextdev = curdev->next;
			sysfs_close_device(curdev);
		}
		for (curdrv = bus->drivers; curdrv != NULL;
		     curdrv = nextdrv) {
			nextdrv = curdrv->next;
			sysfs_close_driver(curdrv);
		}
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
static struct sysfs_directory *open_bus_dir(const char *name)
{
	struct sysfs_directory *busdir = NULL, *cur = NULL, *next = NULL;
	char buspath[SYSFS_PATH_MAX];

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(buspath, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_mnt_path(buspath, SYSFS_PATH_MAX)) != 0) {
		dprintf(stderr, "Sysfs not supported on this system\n");
		return NULL;
	}

	strcat(buspath, SYSFS_BUS_DIR);
	strcat(buspath, "/");
	strcat(buspath, name);
	busdir = sysfs_open_directory(buspath);
	if (busdir == NULL) {
		errno = EINVAL;
		dprintf(stderr,"Bus %s not supported on this system\n",
			name);
		return NULL;
	}
	if ((sysfs_read_directory(busdir)) != 0) {
		dprintf(stderr, "Error reading %s bus dir %s\n", name, 
			buspath);
		sysfs_close_directory(busdir);
		return NULL;
	}
	/* read in devices and drivers subdirs */
	for (cur = busdir->subdirs; cur != NULL; cur = next) {
		next = cur->next;
		if ((sysfs_read_directory(cur)) != 0)
			continue;
	}

	return busdir;
}

/**
 * add_dev_to_bus: adds a bus device to bus device list
 * @bus: bus to add the device
 * @dev: device to add
 */
static void add_dev_to_bus(struct sysfs_bus *bus, struct sysfs_device *dev)
{
	if (bus != NULL && dev != NULL) {
		dev->next = bus->devices;
		bus->devices = dev;
	}
}

/**
 * add_driver_to_bus: adds a bus driver to bus driver list
 * @bus: bus to add driver to
 * @driver: driver to add
 */
static void add_driver_to_bus(struct sysfs_bus *bus, 
				struct sysfs_driver *driver)
{
	if (bus != NULL && driver != NULL) {
		driver->next = bus->drivers;
		bus->drivers = driver;
	}
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
	struct sysfs_dlink *curl = NULL, *nextl = NULL;
	char dirname[SYSFS_NAME_LEN];

	if (bus == NULL || bus->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (cur = bus->directory->subdirs; cur != NULL; cur = cur->next) {
		memset(dirname, 0, SYSFS_NAME_LEN);
		if ((sysfs_get_name_from_path(cur->path, dirname,
		    SYSFS_NAME_LEN)) != 0)
			continue;
		if (strcmp(dirname, SYSFS_DEVICES_NAME) != 0)
			continue;
		for (curl = cur->links; curl != NULL; curl = nextl) {
			nextl = curl->next;
			bdev = sysfs_open_device(curl->target->path);
			if (bdev == NULL) {
				dprintf(stderr, "Error opening device at %s\n",
					curl->target->path);
				continue;
			}
			add_dev_to_bus(bus, bdev);
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
	struct sysfs_directory *cur = NULL, *next = NULL;
	struct sysfs_directory *cursub = NULL, *nextsub = NULL;
	char dirname[SYSFS_NAME_LEN];

	if (bus == NULL || bus->directory == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (cur = bus->directory->subdirs; cur != NULL; cur = next) {
		next = cur->next;
		memset(dirname, 0, SYSFS_NAME_LEN);
		if ((sysfs_get_name_from_path(cur->path, dirname,
		    SYSFS_NAME_LEN)) != 0)
			continue;
		if (strcmp(dirname, SYSFS_DRIVERS_NAME) != 0)
			continue;
		for (cursub = cur->subdirs; cursub != NULL; cursub = nextsub) {
			nextsub = cursub->next;
			driver = sysfs_open_driver(cursub->path);
			if (driver == NULL) {
				dprintf(stderr, "Error opening driver at %s\n",
					cursub->path);
				continue;
			}
			add_driver_to_bus(bus, driver);
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
static int match_bus_device_to_driver(struct sysfs_driver *driver, char *busid)
{
	struct sysfs_dlink *cur = NULL, *next = NULL;
	int found = 0;

	if (driver == NULL || driver->directory == NULL || busid == NULL) {
		errno = EINVAL;
		return found;
	}
	for (cur = driver->directory->links; cur != NULL && found == 0;
	     cur = next) {
		next = cur->next;
		if ((strcmp(cur->name, busid)) == 0)
			found++;
	}
	return found;
}

/**
 * link_bus_devices_to_drivers: goes through and links devices to drivers
 * @bus: bus to link
 */
static void link_bus_devices_to_drivers(struct sysfs_bus *bus)
{
	struct sysfs_device *dev = NULL, *nextdev = NULL;
	struct sysfs_driver *drv = NULL, *nextdrv = NULL;
	
	if (bus != NULL && bus->devices != NULL && bus->drivers != NULL) {
		for (dev = bus->devices; dev != NULL; dev = nextdev) {
			nextdev = dev->next;

			for (drv = bus->drivers; drv != NULL; drv = nextdrv) {
				nextdrv = drv->next;
				if ((match_bus_device_to_driver(drv, 
				    dev->bus_id)) != 0) {
					dev->driver = drv;
					drv->device = dev;
				}
			}
		}
	}
}

/**
 * sysfs_open_bus: opens specific bus and all its devices on system
 * returns sysfs_bus structure with success or NULL with error.
 */
struct sysfs_bus *sysfs_open_bus(const char *name)
{
	struct sysfs_bus *bus = NULL;
	struct sysfs_directory *busdir = NULL;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	bus = alloc_bus();
	if (bus == NULL) {
		perror("malloc");
		return NULL;
	}
	strcpy(bus->name, name);	
	busdir = open_bus_dir(name);
	if (busdir == NULL) {
		dprintf(stderr,"Invalid bus, %s not supported on this system\n",
			name);
		sysfs_close_bus(bus);
		return NULL;
	}
	bus->directory = busdir;
	if ((get_all_bus_devices(bus)) != 0) {
		dprintf(stderr, "Error reading %s bus devices\n", name);
		sysfs_close_bus(bus);
		return NULL;
	}
	if ((get_all_bus_drivers(bus)) != 0) {
		dprintf(stderr, "Error reading %s bus drivers\n", name);
		sysfs_close_bus(bus);
		return NULL;
	}
	link_bus_devices_to_drivers(bus);

	return bus;
}
