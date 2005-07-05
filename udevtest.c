/*
 * udevtest.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_sysfs.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "udev_rules.h"
#include "logging.h"


#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	if (format[strlen(format)-1] != '\n')
		printf("\n");
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	struct udev_rules rules;
	struct sysfs_class_device *class_dev;
	char *devpath;
	char path[PATH_SIZE];
	char temp[PATH_SIZE];
	struct udevice udev;
	char *subsystem = NULL;

	info("version %s", UDEV_VERSION);

	/* initialize our configuration */
	udev_init_config();
	if (udev_log_priority < LOG_INFO)
		udev_log_priority = LOG_INFO;

	if (argc != 3) {
		info("Usage: udevtest <devpath> <subsystem>");
		return 1;
	}

	/* remove sysfs_path if given */
	if (strncmp(argv[1], sysfs_path, strlen(sysfs_path)) == 0)
		devpath = &argv[1][strlen(sysfs_path)] ;
	else
		if (argv[1][0] != '/') {
			/* prepend '/' if missing */
			snprintf(temp, sizeof(temp), "/%s", argv[1]);
			temp[sizeof(temp)-1] = '\0';
			devpath = temp;
		} else
			devpath = argv[1];

	subsystem = argv[2];
	setenv("DEVPATH", devpath, 1);
	setenv("SUBSYSTEM", subsystem, 1);
	setenv("ACTION", "add", 1);
	info("looking at device '%s' from subsystem '%s'", devpath, subsystem);

	/* initialize the naming deamon */
	udev_rules_init(&rules, 0);

	/* fill in values and test_run flag*/
	udev_init_device(&udev, devpath, subsystem, "add");

	/* open the device */
	snprintf(path, sizeof(path), "%s%s", sysfs_path, udev.devpath);
	path[sizeof(path)-1] = '\0';
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		info("sysfs_open_class_device_path failed");
		return 1;
	}
	info("opened class_dev->name='%s'", class_dev->name);

	if (udev.type == DEV_BLOCK || udev.type == DEV_CLASS)
		udev.devt = get_devt(class_dev);

	/* simulate node creation with test flag */
	udev.test_run = 1;
	if (udev.type == DEV_NET || udev.devt) {
		udev_rules_get_name(&rules, &udev, class_dev);
		udev_add_device(&udev, class_dev);
	} else
		info("only char and block devices with a dev-file are supported by this test program");
	sysfs_close_class_device(class_dev);

	return 0;
}
