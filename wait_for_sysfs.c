/*
 * wait_for_sysfs.c  - small program to delay the execution
 *		       of /etc/hotplug.d/ programs, until sysfs
 *		       is fully populated by the kernel. Depending on
 *		       the type of device, we wait for all expected
 *		       directories and then just exit.
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

#include "logging.h"
#include "udev_version.h"
#include "libsysfs/sysfs/libsysfs.h"

#ifndef FILENAME_MAX
#define FILENAME_MAX	4096
#endif

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

#define WAIT_MAX_SECONDS		5
#define WAIT_LOOP_PER_SECOND		20

/* wait for specific file to show up, normally the "dev"-file */
static int wait_for_class_device_attributes(struct sysfs_class_device *class_dev,
					    const char **error)
{
	static struct class_file {
		char *subsystem;
		char *file;
	} class_files[] = {
		{ .subsystem = "net",		.file = "ifindex" },
		{ .subsystem = "scsi_host",	.file = "unique_id" },
		{ .subsystem = "scsi_device",	.file = NULL },
		{ .subsystem = "pcmcia_socket",	.file = "card_type" },
		{ .subsystem = "usb_host",	.file = NULL },
		{ .subsystem = "bluetooth",	.file = "address" },
		{ .subsystem = "firmware",	.file = "data" },
		{ .subsystem = "i2c-adapter",	.file = NULL },
		{ .subsystem = "pci_bus",	.file = NULL },
		{ .subsystem = "ieee1394",	.file = NULL },
		{ .subsystem = "ieee1394_host",	.file = NULL },
		{ .subsystem = "ieee1394_node",	.file = NULL },
		{ NULL, NULL }
	};
	struct class_file *classfile;
	char *file = "dev";
	char filename[FILENAME_MAX];
	int loop;

	/* look if we want to look for another file instead of "dev" */
	for (classfile = class_files; classfile->subsystem != NULL; classfile++) {
		if (strcmp(class_dev->classname, classfile->subsystem) == 0) {
			if (classfile->file == NULL) {
				dbg("class '%s' has no file to wait for", class_dev->classname);
				return 0;
			}
			file = classfile->file;
			break;
		}
	}

	strcpy(filename, class_dev->path);
	strcat(filename, "/");
	strcat(filename, file);
	dbg("looking at class '%s' for specific file '%s' with full name %s", class_dev->classname, class_dev->path, filename);

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		struct stat stats;

		if (stat(class_dev->path, &stats) == -1) {
			dbg("'%s' now disappeared (probably remove has beaten us)", class_dev->path);
			return -ENODEV;
		}

		if (stat(filename, &stats) == 0) {
			dbg("class '%s' specific file '%s' found", class_dev->classname, file);
			return 0;
		}

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	dbg("error: getting class '%s' specific file '%s'", class_dev->classname, file);
	*error = "class specific file unavailable";
	return -ENOENT;
}

/* check if we need to wait for a physical device */
static int class_device_expect_no_device_link(struct sysfs_class_device *class_dev)
{
	/* list of devices without a "device" symlink to the physical device
	 * if device is set to NULL, no devices in that subsystem has a link */
	static struct class_device {
		char *subsystem;
		char *device;
	} class_device[] = {
		{ .subsystem = "block",		.device = "double" },
		{ .subsystem = "block",		.device = "nb" },
		{ .subsystem = "block",		.device = "ram" },
		{ .subsystem = "block",		.device = "loop" },
		{ .subsystem = "block",		.device = "fd" },
		{ .subsystem = "block",		.device = "md" },
		{ .subsystem = "block",		.device = "dos_cd" },
		{ .subsystem = "block",		.device = "rflash" },
		{ .subsystem = "block",		.device = "rom" },
		{ .subsystem = "block",		.device = "rrom" },
		{ .subsystem = "block",		.device = "flash" },
		{ .subsystem = "block",		.device = "msd" },
		{ .subsystem = "block",		.device = "sbpcd" },
		{ .subsystem = "block",		.device = "pcd" },
		{ .subsystem = "block",		.device = "pf" },
		{ .subsystem = "block",		.device = "scd" },
		{ .subsystem = "block",		.device = "ubd" },
		{ .subsystem = "input",		.device = "event" },
		{ .subsystem = "input",		.device = "mice" },
		{ .subsystem = "input",		.device = "mouse" },
		{ .subsystem = "input",		.device = "ts" },
		{ .subsystem = "vc",		.device = NULL },
		{ .subsystem = "tty",		.device = NULL },
		{ .subsystem = "cpuid",		.device = "cpu" },
		{ .subsystem = "graphics",	.device = "fb" },
		{ .subsystem = "mem",		.device = NULL },
		{ .subsystem = "misc",		.device = NULL },
		{ .subsystem = "msr",		.device = NULL },
		{ .subsystem = "netlink",	.device = NULL },
		{ .subsystem = "net",		.device = "sit" },
		{ .subsystem = "net",		.device = "lo" },
		{ .subsystem = "net",		.device = "tap" },
		{ .subsystem = "net",		.device = "ipsec" },
		{ .subsystem = "net",		.device = "dummy" },
		{ .subsystem = "net",		.device = "irda" },
		{ .subsystem = "net",		.device = "ppp" },
		{ .subsystem = "ppp",		.device = NULL },
		{ .subsystem = "sound",		.device = NULL },
		{ .subsystem = "printer",	.device = "lp" },
		{ .subsystem = "nvidia",	.device = NULL },
		{ .subsystem = "video4linux",	.device = "vbi" },
		{ .subsystem = "lirc",		.device = NULL },
		{ .subsystem = "firmware",	.device = NULL },
		{ .subsystem = "drm",		.device = NULL },
		{ .subsystem = "pci_bus",	.device = NULL },
		{ .subsystem = "ieee1394",	.device = NULL },
		{ .subsystem = "ieee1394_host",	.device = NULL },
		{ .subsystem = "ieee1394_node",	.device = NULL },
		{ .subsystem = "raw",		.device = NULL },
		{ NULL, NULL }
	};
	struct class_device *classdevice;
	int len;

	for (classdevice = class_device; classdevice->subsystem != NULL; classdevice++) {
		if (strcmp(class_dev->classname, classdevice->subsystem) == 0) {
			/* see if no device in this class is expected to have a device-link */
			if (classdevice->device == NULL)
				return 1;

			len = strlen(classdevice->device);

			/* see if device name matches */
			if (strncmp(class_dev->name, classdevice->device, len) != 0)
				continue;

			/* exact name match */
			if (strlen(class_dev->name) == len)
				return 1;

			/* name match with instance number */
			if (isdigit(class_dev->name[len]))
				return 1;
		}
	}

	return 0;
}

/* skip waiting for the bus */
static int class_device_expect_no_bus(struct sysfs_class_device *class_dev)
{
	static char *devices_without_bus[] = {
		"scsi_host",
		"i2c-adapter",
		NULL
	};
	char **device;

	for (device = devices_without_bus; *device != NULL; device++) {
		int len = strlen(*device);

		if (strncmp(class_dev->classname, *device, len) == 0)
			return 1;
	}

	return 0;
}

/* wait for the bus and for a bus specific file to show up */
static int wait_for_bus_device(struct sysfs_device *devices_dev,
			       const char **error)
{
	static struct bus_file {
		char *bus;
		char *file;
	} bus_files[] = {
		{ .bus = "scsi",	.file = "vendor" },
		{ .bus = "usb",		.file = "idVendor" },
		{ .bus = "usb",		.file = "iInterface" },
		{ .bus = "usb",		.file = "bNumEndpoints" },
		{ .bus = "usb-serial",	.file = "detach_state" },
		{ .bus = "ide",		.file = "detach_state" },
		{ .bus = "pci",		.file = "vendor" },
		{ .bus = "platform",	.file = "detach_state" },
		{ .bus = "i2c",		.file = "detach_state" },
		{ NULL }
	};
	struct bus_file *busfile;
	int loop;

	/* wait for the bus device link to the devices device */
	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		if (sysfs_get_device_bus(devices_dev) == 0)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	if (loop == 0) {
		dbg("error: getting bus device link");
		*error = "no bus device link";
		return -1;
	}
	dbg("bus device link found for bus '%s'", devices_dev->bus);

	/* wait for a bus specific file to show up */
	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		int found = 0;

		for (busfile = bus_files; busfile->bus != NULL; busfile++) {
			if (strcmp(devices_dev->bus, busfile->bus) == 0) {
				found = 1;
				dbg("looking at bus '%s' for specific file '%s'", devices_dev->bus, busfile->file);
				if (sysfs_get_device_attr(devices_dev, busfile->file) != NULL) {
					dbg("bus '%s' specific file '%s' found", devices_dev->bus, busfile->file);
					return 0;
				}
			}
		}
		if (found == 0) {
			*error = "unknown bus";
			info("error: unknown bus, please report to "
			     "<linux-hotplug-devel@lists.sourceforge.net> '%s'", devices_dev->bus);
			return -1;
		}
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	dbg("error: getting bus '%s' specific file '%s'", devices_dev->bus, busfile->file);
	*error = "bus specific file unavailable";
	return -1;
}


static struct sysfs_class_device *open_class_device(const char *path)
{
	struct sysfs_class_device *class_dev;
	int loop;

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		class_dev = sysfs_open_class_device_path(path);
		if (class_dev)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	return (class_dev);
}

static int wait_for_class_device(struct sysfs_class_device *class_dev,
				 const char **error)
{
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_device *devices_dev = NULL;
	int loop;

	if (wait_for_class_device_attributes(class_dev, error) != 0)
		return -ENOENT;

	/* skip devices without devices-link */
	if (class_device_expect_no_device_link(class_dev)) {
		dbg("no device symlink expected for '%s', ", class_dev->name);
		return -ENODEV;
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
		*error = "no device symlink";
		return -ENODEV;
	}
	dbg("device symlink found pointing to '%s'", devices_dev->path);

	/* wait for the bus value */
	if (class_device_expect_no_bus(class_dev)) {
		dbg("no bus device expected for '%s', ", class_dev->classname);
		return 0;
	} else {
		return wait_for_bus_device(devices_dev, error);
	}
}

static struct sysfs_device *open_devices_device(const char *path)
{
	struct sysfs_device *devices_dev;
	int loop;

	loop = WAIT_MAX_SECONDS * WAIT_LOOP_PER_SECOND;
	while (--loop) {
		devices_dev = sysfs_open_device_path(path);
		if (devices_dev)
			break;

		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}

	return(devices_dev);
}

int main(int argc, char *argv[], char *envp[])
{
	const char *devpath = "";
	const char *action;
	const char *subsystem;
	char sysfs_path[SYSFS_PATH_MAX];
	char filename[SYSFS_PATH_MAX];
	struct sysfs_class_device *class_dev;
	struct sysfs_device *devices_dev;
	int rc = 0;
	const char *error = NULL;

	logging_init("wait_for_sysfs");

	if (argc != 2) {
		dbg("error: subsystem");
		return 1;
	}
	subsystem = argv[1];

	devpath = getenv ("DEVPATH");
	if (!devpath) {
		dbg("error: no DEVPATH");
		rc = 1;
		goto exit;
	}

	action = getenv ("ACTION");
	if (!action) {
		dbg("error: no ACTION");
		rc = 1;
		goto exit;
	}

	/* we only wait on an add event */
	if (strcmp(action, "add") != 0) {
		dbg("no add ACTION");
		goto exit;
	}

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		dbg("error: no sysfs path");
		rc = 2;
		goto exit;
	}

	if ((strncmp(devpath, "/block/", 7) == 0) || (strncmp(devpath, "/class/", 7) == 0)) {
		snprintf(filename, SYSFS_PATH_MAX-1, "%s%s", sysfs_path, devpath);
		filename[SYSFS_PATH_MAX-1] = '\0';

		/* open the class device we are called for */
		class_dev = open_class_device(filename);
		if (!class_dev) {
			dbg("error: class device unavailable (probably remove has beaten us)");
			goto exit;
		}
		dbg("class device opened '%s'", filename);

		/* wait for the class device with possible physical device and bus */
		wait_for_class_device(class_dev, &error);

		sysfs_close_class_device(class_dev);

	} else if ((strncmp(devpath, "/devices/", 9) == 0)) {
		snprintf(filename, SYSFS_PATH_MAX-1, "%s%s", sysfs_path, devpath);
		filename[SYSFS_PATH_MAX-1] = '\0';

		/* open the path we are called for */
		devices_dev = open_devices_device(filename);
		if (!devices_dev) {
			dbg("error: devices device unavailable (probably remove has beaten us)");
			goto exit;
		}
		dbg("devices device opened '%s'", filename);

		/* wait for the bus value */
		wait_for_bus_device(devices_dev, &error);

		sysfs_close_device(devices_dev);

	} else {
		dbg("unhandled sysfs path, no need to wait");
	}

exit:
	if (error) {
		info("either wait_for_sysfs (udev %s) needs an update to handle the device '%s' "
		     "properly (%s) or the sysfs-support of your device's driver needs to be fixed, "
		     "please report to <linux-hotplug-devel@lists.sourceforge.net>",
		     UDEV_VERSION, devpath, error);
		rc =3;
	} else {
		dbg("result: waiting for sysfs successful '%s'", devpath);
	}

	logging_close();
	exit(rc);
}
