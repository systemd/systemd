/*
 * sysfs_driver.c
 *
 * Driver utility functions for libsysfs
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

static void sysfs_close_driver_device(void *device)
{
	sysfs_close_device((struct sysfs_device *)device);
}

/**
 * sysfs_close_driver: closes driver and deletes device lists too
 * @driver: driver to close
 */
void sysfs_close_driver(struct sysfs_driver *driver)
{
	if (driver) {
		if (driver->devices) 
			dlist_destroy(driver->devices);
		if (driver->attrlist)
			dlist_destroy(driver->attrlist);
		free(driver);
	}
}

/**
 * alloc_driver: allocates and initializes driver
 * returns struct sysfs_driver with success and NULL with error.
 */
static struct sysfs_driver *alloc_driver(void)
{
	return (struct sysfs_driver *)calloc(1, sizeof(struct sysfs_driver));
}

/**
 * get_driver_bus: gets bus the driver is on
 * Returns 0 on success and 1 on error
 */
static int get_driver_bus(struct sysfs_driver *drv)
{
	char drvpath[SYSFS_PATH_MAX], *c = NULL;
	
	if (!drv) {
		errno = EINVAL;
		return 1;
	}

	safestrcpy(drvpath, drv->path);
	c = strstr(drvpath, SYSFS_DRIVERS_NAME);
	if (c == NULL)
		return 1;
	*--c = '\0';
	c = strstr(drvpath, SYSFS_BUS_NAME);
	if (c == NULL)
		return 1;
	c = strstr(c, "/");
	if (c == NULL)
		return 1;
	c++;
	safestrcpy(drv->bus, c);
	return 0;
}

/**
 * sysfs_get_driver_attr: searches drv's attributes by name
 * @drv: driver to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference with success or NULL with error.
 */
struct sysfs_attribute *sysfs_get_driver_attr(struct sysfs_driver *drv,
						const char *name)
{
	if (!drv || !name) {
		errno = EINVAL;
		return NULL;
	}
	return get_attribute(drv, (char *)name);
}

/**
 * sysfs_get_driver_attributes: gets list of driver attributes
 * @dev: driver whose attributes list is needed
 * returns dlist of attributes on success or NULL on error
 */
struct dlist *sysfs_get_driver_attributes(struct sysfs_driver *drv)
{
	if (!drv) {
		errno = EINVAL;
		return NULL;
	}
	return get_attributes_list(drv);
}

/**
 * sysfs_open_driver_path: opens and initializes driver structure
 * @path: path to driver directory
 * returns struct sysfs_driver with success and NULL with error
 */
struct sysfs_driver *sysfs_open_driver_path(const char *path)
{
	struct sysfs_driver *driver = NULL;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	if (sysfs_path_is_dir(path)) {
		dprintf("Invalid path to driver: %s\n", path);
		return NULL;
	}
	driver = alloc_driver();
	if (!driver) {
		dprintf("Error allocating driver at %s\n", path);
		return NULL;
	}
	if (sysfs_get_name_from_path(path, driver->name, SYSFS_NAME_LEN)) {
		dprintf("Error getting driver name from path\n");
		free(driver);
		return NULL;
	}
	safestrcpy(driver->path, path);
	if (sysfs_remove_trailing_slash(driver->path)) {
		dprintf("Invalid path to driver %s\n", driver->path);
		sysfs_close_driver(driver);
		return NULL;
	}
	if (get_driver_bus(driver)) {
		dprintf("Could not get the bus driver is on\n");
		sysfs_close_driver(driver);
		return NULL;
	}

	return driver;
}

/**
 * get_driver_path: looks up the bus the driver is on and builds path to
 * 		the driver.
 * @bus: bus on which to search
 * @drv: driver to look for
 * @path: buffer to return path to driver
 * @psize: size of "path"
 * Returns 0 on success and -1 on error
 */
static int get_driver_path(const char *bus, const char *drv, 
			char *path, size_t psize)
{
	if (!bus || !drv || !path || psize == 0) {
		errno = EINVAL;
		return -1;
	}
	if (sysfs_get_mnt_path(path, psize)) {
		dprintf("Error getting sysfs mount path\n");
		return -1;
	}
	safestrcatmax(path, "/", psize);
	safestrcatmax(path, SYSFS_BUS_NAME, psize);
	safestrcatmax(path, "/", psize);
	safestrcatmax(path, bus, psize);
	safestrcatmax(path, "/", psize);
	safestrcatmax(path, SYSFS_DRIVERS_NAME, psize);
	safestrcatmax(path, "/", psize);
	safestrcatmax(path, drv, psize);
	return 0;
}

/**
 * sysfs_open_driver: open driver by name, given its bus
 * @bus_name: Name of the bus
 * @drv_name: Name of the driver
 * Returns the sysfs_driver reference on success and NULL on failure
 */
struct sysfs_driver *sysfs_open_driver(const char *bus_name, 
			const char *drv_name)
{
	char path[SYSFS_PATH_MAX];
	struct sysfs_driver *driver = NULL;

	if (!drv_name || !bus_name) {
		errno = EINVAL;
		return NULL;
	}

	memset(path, 0, SYSFS_PATH_MAX);
	if (get_driver_path(bus_name, drv_name, path, SYSFS_PATH_MAX)) {
		dprintf("Error getting to driver %s\n", drv_name);
		return NULL;
	}
	driver = sysfs_open_driver_path(path);
	if (!driver) {
		dprintf("Error opening driver at %s\n", path);
		return NULL;
	}
	return driver;
}

/**
 * sysfs_get_driver_devices: gets list of devices that use the driver
 * @drv: sysfs_driver whose device list is needed
 * Returns dlist of struct sysfs_device on success and NULL on failure
 */
struct dlist *sysfs_get_driver_devices(struct sysfs_driver *drv)
{
	char *ln = NULL;
	struct dlist *linklist = NULL;
	struct sysfs_device *dev = NULL;

	if (!drv) {
		errno = EINVAL;
		return NULL;
	}

	linklist = read_dir_links(drv->path);
	if (linklist) {
		dlist_for_each_data(linklist, ln, char) {
			
			if (!strncmp(ln, SYSFS_MODULE_NAME, strlen(ln)))
				continue;

			dev = sysfs_open_device(drv->bus, ln);
			if (!dev) {
				dprintf("Error opening driver's device\n");
				sysfs_close_list(linklist);
				return NULL;
			}
			if (!drv->devices) {
				drv->devices = dlist_new_with_delete
					(sizeof(struct sysfs_device),
					 sysfs_close_driver_device);
				if (!drv->devices) {
					dprintf("Error creating device list\n");
					sysfs_close_list(linklist);
					return NULL;
				}
			}
			dlist_unshift_sorted(drv->devices, dev, sort_list);
		}
		sysfs_close_list(linklist);
	}
	return drv->devices;
}
