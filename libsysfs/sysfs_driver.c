/*
 * sysfs_driver.c
 *
 * Driver utility functions for libsysfs
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
 * sysfs_close_driver: closes and cleans up driver structure
 * @driver: driver to close
 */
void sysfs_close_driver(struct sysfs_driver *driver)
{
	if (driver != NULL) {
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
struct sysfs_driver *sysfs_open_driver(const char *path)
{
	struct sysfs_driver *driver = NULL;
	struct sysfs_directory *sdir = NULL;
	char devname[SYSFS_NAME_LEN];

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	sdir = sysfs_open_directory(path);
	if (sdir == NULL) {
		dprintf (stderr, "Error opening directory %s\n", path);
		return NULL;
	}
	if ((sysfs_read_directory(sdir)) != 0) {
		dprintf (stderr, "Error reading directory %s\n", path);
		sysfs_close_directory(sdir);
		return NULL;
	}
	driver = alloc_driver();
	if (driver == NULL) {
		dprintf(stderr, "Error allocating driver at %s\n", path);
		sysfs_close_directory(sdir);
		return NULL;
	}
	if ((sysfs_get_name_from_path(path, devname, SYSFS_NAME_LEN)) != 0) {
		dprintf (stderr, "Error reading directory %s\n", path);
		sysfs_close_directory(sdir);
		free(driver);
		return NULL;
	}
	strncpy(driver->name, devname, sizeof(driver->name));
	driver->directory = sdir;	
	
	return driver;
}
