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
#include "udev_sysfs.h"
#include "libsysfs/sysfs/libsysfs.h"

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

int main(int argc, char *argv[], char *envp[])
{
	const char *devpath = "";
	const char *action;
	const char *subsystem;
	char sysfs_mnt_path[SYSFS_PATH_MAX];
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

	if (sysfs_get_mnt_path(sysfs_mnt_path, SYSFS_PATH_MAX) != 0) {
		dbg("error: no sysfs path");
		rc = 2;
		goto exit;
	}

	if ((strncmp(devpath, "/block/", 7) == 0) || (strncmp(devpath, "/class/", 7) == 0)) {
		snprintf(filename, SYSFS_PATH_MAX-1, "%s%s", sysfs_mnt_path, devpath);
		filename[SYSFS_PATH_MAX-1] = '\0';

		/* skip bad events where we get no device for the class */
		if (strncmp(devpath, "/class/", 7) == 0 && strchr(&devpath[7], '/') == NULL) {
			dbg("no device name for '%s', bad event", devpath);
			goto exit;
		}

		/* open the class device we are called for */
		class_dev = open_class_device_wait(filename);
		if (!class_dev) {
			dbg("error: class device unavailable (probably remove has beaten us)");
			goto exit;
		}
		dbg("class device opened '%s'", filename);

		/* wait for the class device with possible physical device and bus */
		wait_for_class_device(class_dev, &error);

		sysfs_close_class_device(class_dev);

	} else if ((strncmp(devpath, "/devices/", 9) == 0)) {
		snprintf(filename, SYSFS_PATH_MAX-1, "%s%s", sysfs_mnt_path, devpath);
		filename[SYSFS_PATH_MAX-1] = '\0';

		/* open the path we are called for */
		devices_dev = open_devices_device_wait(filename);
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
