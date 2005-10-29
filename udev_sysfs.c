/*
 * udev_sysfs.c  - sysfs linux kernel specific knowledge
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_version.h"
#include "udev_sysfs.h"
#include "udev_utils.h"
#include "logging.h"

/* list of subsystem specific files, NULL if there is no file to wait for */
dev_t get_devt(struct sysfs_class_device *class_dev)
{
	struct sysfs_attribute *attr = NULL;
	unsigned int major, minor;

	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr == NULL)
		return 0;
	dbg("dev='%s'", attr->value);

	if (sscanf(attr->value, "%u:%u", &major, &minor) != 2)
		return 0;
	dbg("found major=%d, minor=%d", major, minor);

	return makedev(major, minor);
}

/* wait for a devices device specific file to show up */
int wait_for_devices_device(struct sysfs_device *devices_dev,
			const char **error)
{
	static const struct device_file {
		const char *bus;
		const char *file;
	} device_files[] = {
		{ .bus = "scsi",	.file = "vendor" },
		{ .bus = "usb",		.file = "idVendor" },
		{ .bus = "usb",		.file = "iInterface" },
		{ .bus = "usb",		.file = "bNumEndpoints" },
		{ .bus = "usb-serial",	.file = "bus" },
		{ .bus = "ide",		.file = "bus" },
		{ .bus = "pci",		.file = "vendor" },
		{ .bus = "pci_express",	.file = "bus" },
		{ .bus = "platform",	.file = "bus" },
		{ .bus = "pcmcia",	.file = "bus" },
		{ .bus = "i2c",		.file = "bus" },
		{ .bus = "ieee1394",	.file = "node_count" },
		{ .bus = "ieee1394",	.file = "nodeid" },
		{ .bus = "ieee1394",	.file = "address" },
		{ .bus = "bttv-sub",	.file = NULL },
		{ .bus = "pnp",		.file = "bus" },
		{ .bus = "eisa",	.file = "bus" },
		{ .bus = "serio",	.file = "bus" },
		{ .bus = "pseudo",	.file = "bus" },
		{ .bus = "mmc",		.file = "bus" },
		{ .bus = "macio",	.file = "bus" },
		{ .bus = "of_platform",	.file = "bus" },
		{ .bus = "vio",		.file = "bus" },
		{ .bus = "ecard",	.file = "bus" },
		{ .bus = "sa1111-rab",	.file = "bus" },
		{ .bus = "amba",	.file = "bus" },
		{ .bus = "locomo-bus",	.file = "bus" },
		{ .bus = "logicmodule",	.file = "bus" },
		{ .bus = "parisc",	.file = "bus" },
		{ .bus = "ocp",		.file = "bus" },
		{ .bus = "dio",		.file = "bus" },
		{ .bus = "MCA",		.file = "bus" },
		{ .bus = "wl",		.file = "bus" },
		{ .bus = "ccwgroup",	.file = "bus" },
		{ .bus = "css",		.file = "bus" },
		{ .bus = "ccw",		.file = "bus" },
		{ .bus = "iucv",	.file = "bus" },
		{ NULL, NULL }
	};
	const struct device_file *devicefile = NULL;
	int loop;

	if (getenv("PHYSDEVBUS") == NULL) {
		dbg("the kernel says, that there is no bus for '%s'", devices_dev->path);
		return 0;
	}

	/* wait for the bus device link to the devices device */
	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		if (sysfs_get_device_bus(devices_dev) == 0)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	if (loop == 0) {
		dbg("error: getting bus device link");
		if (error)
			*error = "no bus device link";
		return -1;
	}
	dbg("bus device link found for bus '%s'", devices_dev->bus);

	/* wait for a bus device specific file to show up */
	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		int found_bus_type = 0;

		for (devicefile = device_files; devicefile->bus != NULL; devicefile++) {
			if (strcmp(devices_dev->bus, devicefile->bus) == 0) {
				char filename[PATH_SIZE];
				struct stat stats;

				if (devicefile->file == NULL) {
					dbg("bus '%s' has no file to wait for", devices_dev->bus);
					return 0;
				}

				found_bus_type = 1;
				snprintf(filename, sizeof(filename), "%s/%s", devices_dev->path, devicefile->file);
				filename[sizeof(filename)-1] = '\0';
				dbg("looking at bus '%s' device for specific file '%s'", devices_dev->bus, filename);

				if (stat(filename, &stats) == 0) {
					dbg("bus '%s' device specific file '%s' found", devices_dev->bus, devicefile->file);
					return 0;
				}
			}
		}
		if (found_bus_type == 0) {
			if (error)
				*error = "unknown bus";
			info("error: unknown bus, please report to "
			     "<linux-hotplug-devel@lists.sourceforge.net> '%s'", devices_dev->bus);
			return -1;
		}
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	dbg("error: getting '%s' device specific file '%s'", devices_dev->bus, devicefile->file);
	if (error)
		*error = "bus device specific file unavailable";
	return -1;
}


struct sysfs_class_device *wait_class_device_open(const char *path)
{
	struct sysfs_class_device *class_dev = NULL;
	int loop;

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		class_dev = sysfs_open_class_device_path(path);
		if (class_dev)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	return class_dev;
}

int wait_for_class_device(struct sysfs_class_device *class_dev,
			  const char **error)
{
	const struct subsystem_file {
		const char *subsystem;
		const char *file;
	} subsystem_files[] = {
		{ .subsystem = "net",		.file = "ifindex" },
		{ .subsystem = "scsi_host",	.file = "unique_id" },
		{ .subsystem = "pcmcia_socket",	.file = "card_type" },
		{ .subsystem = "bluetooth",	.file = "address" },
		{ .subsystem = "firmware",	.file = "data" },
		{ .subsystem = "fc_transport",	.file = "port_id" },
		{ .subsystem = "fc_host",	.file = "port_id" },
		{ .subsystem = "spi_transport",	.file = "width" },
		{ .subsystem = "spi_host",	.file = "width" },
		{ NULL, NULL }
	};

	const struct subsystem_file *subsys_file;
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_device *devices_dev = NULL;
	char filename[PATH_SIZE];
	int loop;

	/* look if we want to wait for a file  */
	for (subsys_file = subsystem_files; subsys_file->subsystem != NULL; subsys_file++)
		if (strcmp(class_dev->classname, subsys_file->subsystem) == 0)
			break;

	if (subsys_file->file == NULL) {
		dbg("class '%s' has no file to wait for", class_dev->classname);
		return 0;
	}

	snprintf(filename, sizeof(filename), "%s/%s", class_dev->path, subsys_file->file);
	filename[sizeof(filename)-1] = '\0';
	dbg("looking at class '%s' for specific file '%s'", class_dev->classname, filename);

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		struct stat stats;

		if (stat(class_dev->path, &stats) == -1) {
			dbg("'%s' now disappeared (probably remove has beaten us)", class_dev->path);
			return -ENODEV;
		}

		if (stat(filename, &stats) == 0) {
			dbg("class '%s' specific file '%s' found", class_dev->classname, subsys_file->file);
			return 0;
		}

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	dbg("error: getting class '%s' specific file '%s'", class_dev->classname, subsys_file->file);
	if (error)
		*error = "class specific file unavailable";
	return -1;

	/* skip devices without devices-link */
	if (getenv("PHYSDEVPATH") == NULL) {
		dbg("the kernel says, that there is no physical device for '%s'", class_dev->path);
		return 1;
	}

	/* the symlink may be on the parent device */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent)
		dbg("looking at parent device for device link '%s'", class_dev_parent->path);

	/* wait for the symlink to the devices device */
	dbg("waiting for symlink to devices device");
	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		if (class_dev_parent)
			devices_dev = sysfs_get_classdev_device(class_dev_parent);
		else
			devices_dev = sysfs_get_classdev_device(class_dev);

		if (devices_dev)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	if (!devices_dev) {
		dbg(" error: no devices device symlink found");
		if (error)
			*error = "no device symlink";
		return -ENODEV;
	}
	dbg("device symlink found pointing to '%s'", devices_dev->path);

	return wait_for_devices_device(devices_dev, error);
}

struct sysfs_device *wait_devices_device_open(const char *path)
{
	struct sysfs_device *devices_dev = NULL;
	int loop;

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		devices_dev = sysfs_open_device_path(path);
		if (devices_dev)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	return devices_dev;
}
