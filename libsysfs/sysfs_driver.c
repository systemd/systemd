/*
 * sysfs_driver.c
 *
 * Driver utility functions for libsysfs
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

static void sysfs_close_driver_by_name_dev(void *device)
{
	sysfs_close_device((struct sysfs_device *)device);
}

/**
 * sysfs_close_driver: closes and cleans up driver structure
 * NOTE: This routine does not deallocate devices list
 * @driver: driver to close
 */
void sysfs_close_driver(struct sysfs_driver *driver)
{
	if (driver != NULL) {
		if (driver->devices != NULL) {
			dlist_for_each(driver->devices) 
				dlist_shift(driver->devices);
			free(driver->devices);
			driver->devices = NULL;
		}
		if (driver->directory != NULL)
			sysfs_close_directory(driver->directory);
		free(driver);
	}
}

/** 
 * sysfs_close_driver_by_name: closes driver and deletes device lists too
 * @driver: driver to close
 */ 
void sysfs_close_driver_by_name(struct sysfs_driver *driver)
{
	if (driver != NULL) {
		if (driver->devices != NULL) 
			dlist_destroy(driver->devices);
		if (driver->directory != NULL)
			sysfs_close_directory(driver->directory);
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
 * sysfs_open_driver: opens and initializes driver structure
 * @path: path to driver directory
 * returns struct sysfs_driver with success and NULL with error
 */
struct sysfs_driver *sysfs_open_driver(const unsigned char *path)
{
	struct sysfs_driver *driver = NULL;
	struct sysfs_directory *sdir = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	sdir = sysfs_open_directory(path);
	if (sdir == NULL) {
		dprintf("Error opening directory %s\n", path);
		return NULL;
	}
	if ((sysfs_read_directory(sdir)) != 0) {
		dprintf("Error reading directory %s\n", path);
		sysfs_close_directory(sdir);
		return NULL;
	}
	driver = alloc_driver();
	if (driver == NULL) {
		dprintf("Error allocating driver at %s\n", path);
		sysfs_close_directory(sdir);
		return NULL;
	}
	strcpy(driver->name, sdir->name);
	driver->directory = sdir;	
	strcpy(driver->path, sdir->path);
	
	return driver;
}

/**
 * sysfs_get_driver_attributes: gets list of attributes for the given driver
 * @driver: sysfs_driver for which attributes are required
 * returns a dlist of attributes corresponding to the driver if present
 * 	NULL otherwise
 */
struct dlist *sysfs_get_driver_attributes(struct sysfs_driver *driver)
{
	if (driver == NULL || driver->directory == NULL)
		return NULL;

	return(driver->directory->attributes);
}

/**
 * sysfs_get_driver_attr: searches driver's attributes by name
 * @drv: driver to look through
 * @name: attribute name to get
 * returns sysfs_attribute reference on success or NULL with error
 */ 
struct sysfs_attribute *sysfs_get_driver_attr(struct sysfs_driver *drv,
					const unsigned char *name)
{
	struct sysfs_attribute *cur = NULL;

        if (drv == NULL || drv->directory == NULL
            || drv->directory->attributes == NULL || name == NULL) {
                errno = EINVAL;
                return NULL;
        }

        cur = sysfs_get_directory_attribute(drv->directory,
		                        (unsigned char *)name);
        if (cur != NULL)
                return cur;

        return NULL;
}

/**
 * sysfs_get_driver_links: gets list of links from the given driver
 * @driver: sysfs_driver for which links list is required
 * returns a dlist of links corresponding to the driver if present
 * 	NULL otherwise
 */
struct dlist *sysfs_get_driver_links(struct sysfs_driver *driver)
{
	if (driver == NULL || driver->directory == NULL)
		return NULL;

	return(driver->directory->links);
}

/**
 * sysfs_open_driver_by_name: open a driver by name and return the bus
 * the driver is on.
 * @drv_name: driver to open
 * @bus: the driver bus
 * @bsize: size of bus buffer
 * returns struct sysfs_driver if found, NULL otherwise
 * NOTE: 
 * 1. Need to call sysfs_close_driver_by_name to free up memory
 * 2. Bus the driver is registered with must be supplied.
 * 	Use sysfs_find_driver_bus() to obtain the bus name
 */
struct sysfs_driver *sysfs_open_driver_by_name(const unsigned char *drv_name,
				const unsigned char *bus, size_t bsize)
{
	struct sysfs_driver *driver = NULL;
	struct sysfs_device *device = NULL;
	struct sysfs_link *curlink = NULL;
	unsigned char path[SYSFS_PATH_MAX];

	if (drv_name == NULL || bus == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(path, 0, SYSFS_PATH_MAX);
	if (sysfs_get_mnt_path(path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount path\n");
		return NULL;
	}
	strcat(path, SYSFS_BUS_DIR);
	strcat(path, "/");
	strcat(path, bus);
	strcat(path, SYSFS_DRIVERS_DIR);
	strcat(path, "/");
	strcat(path, drv_name);
	driver = sysfs_open_driver(path);
	if (driver == NULL) {
		dprintf("Could not open driver %s\n", drv_name);
		return NULL;
	}
	if (driver->directory->links != NULL) {
		dlist_for_each_data(driver->directory->links, curlink, 
							struct sysfs_link) {
			device = sysfs_open_device(curlink->target);
			if (device == NULL) {
				dprintf("Error opening device at %s\n", 
						curlink->target);
				sysfs_close_driver_by_name(driver);
				return NULL;
			}
			strcpy(device->driver_name, drv_name);
			if (driver->devices == NULL) 
				driver->devices = dlist_new_with_delete
						(sizeof(struct sysfs_device),
					 		sysfs_close_driver_by_name_dev);
			dlist_unshift(driver->devices, device);
		}
	}
	return driver;
}

/**
 * get_driver_path: looks up the bus the driver is on and builds path to
 * 		the driver.
 * @drv: driver to look for
 * @path: buffer to return path to driver
 * @psize: size of "path"
 * Returns 0 on success and -1 on error
 */
static int get_driver_path(const unsigned char *drv, 
				unsigned char *path, size_t psize)
{
	unsigned char bus_name[SYSFS_NAME_LEN];

	if (drv == NULL || path == NULL) {
		errno = EINVAL;
		return -1;
	}
	memset(bus_name, 0, SYSFS_NAME_LEN);
	memset(path, 0, SYSFS_PATH_MAX);
	if ((sysfs_find_driver_bus(drv, bus_name, SYSFS_NAME_LEN)) < 0) {
		dprintf("Driver %s not found\n", drv);
		return -1;
	}
	if (sysfs_get_mnt_path(path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount path\n");
		return -1;
	}
	strcat(path, SYSFS_BUS_DIR);
	strcat(path, "/");
	strcat(path, bus_name);
	strcat(path, SYSFS_DRIVERS_DIR);
	strcat(path, "/");
	strcat(path, drv);
	fprintf(stdout, "get_driver_path %s\n", path);
	return 0;
}

/**
 * sysfs_write_driver_attr: modify "writable" driver attribute
 * @drv: driver whose attribute has to be modified
 * @attrib: Attribute to be modified
 * @value: Value to change to
 * Returns 0 on success -1 on failure
 */ 
int sysfs_write_driver_attr(unsigned char *drv, unsigned char *attrib,
					unsigned char *value, size_t len)
{
	struct sysfs_attribute *attribute = NULL;
	unsigned char path[SYSFS_PATH_MAX];

	if (drv == NULL || attrib == NULL || value == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(path, 0, SYSFS_PATH_MAX);
	if ((get_driver_path(drv, path, SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to driver %s\n", drv);
		return -1;
	}
	strcat(path, "/");
	strcat(path, attrib);
	attribute = sysfs_open_attribute(path);
        if (attribute == NULL) {
                dprintf("Attribute %s could not be retrieved for driver %s\n",
							attrib, drv);
		return -1;
	}
	if (attribute->method & SYSFS_METHOD_SHOW) {
		if ((sysfs_read_attribute(attribute)) != 0) {
			dprintf("Error reading attribute %s for driver %s\n",
					attrib, drv);
			sysfs_close_attribute(attribute);
			return -1;
		}
	}
	if ((sysfs_write_attribute(attribute, value, len)) < 0) {
		dprintf("Error setting %s to %s\n", attrib, value);
		sysfs_close_attribute(attribute);
		return -1;
	}
	sysfs_close_attribute(attribute);
	return 0;
}

/**
 * sysfs_read_driver_attr: read the user supplied driver attribute
 * @drv: driver whose attribute has to be read
 * @attrib: Attribute to be read
 * @value: Buffer to return the read value
 * @len: Length of the buffer "value"
 * Returns 0 on success -1 on failure
 */ 
int sysfs_read_driver_attr(unsigned char *drv, unsigned char *attrib,
					unsigned char *value, size_t len)
{
	struct sysfs_attribute *attribute = NULL;
	unsigned char path[SYSFS_PATH_MAX];

	if (drv == NULL || attrib == NULL || value == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(path, 0, SYSFS_NAME_LEN);
	if ((get_driver_path(drv, path, SYSFS_PATH_MAX)) != 0) {
		dprintf("Error getting to driver %s\n", drv);
		return -1;
	}
	strcat(path, "/");
	strcat(path, attrib);
	attribute = sysfs_open_attribute(path);
        if (attribute == NULL) {
		dprintf("Error opening attribute %s for driver %s\n",
				attrib, drv);
		return -1;
	}
	if (!(attribute->method & SYSFS_METHOD_SHOW)) {
		dprintf("Show method not supported for attribute %s\n",
				attrib);
		sysfs_close_attribute(attribute);
		return -1;
	}
	if ((sysfs_read_attribute(attribute)) != 0) {
                dprintf("Error reading attribute %s for driver %s\n", 
				attrib, drv);
		sysfs_close_attribute(attribute);
		return -1;
	}
	if (attribute->len > len) {
		dprintf("Value length %d is larger than supplied buffer %d\n",
				attribute->len, len);
		sysfs_close_attribute(attribute);
		return -1;
	}
	strncpy(value, attribute->value, attribute->len);
	value[(attribute->len)+1] = 0;
	sysfs_close_attribute(attribute);
	return 0;
}

