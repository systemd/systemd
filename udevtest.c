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

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_sysfs.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "namedev.h"
#include "logging.h"


#ifdef USE_LOG
void log_message (int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	if (format[strlen(format)-1] != '\n')
		printf("\n");
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	struct sysfs_class_device *class_dev;
	char *devpath;
	char path[PATH_SIZE];
	char temp[PATH_SIZE];
	struct udevice udev;
	char *subsystem = NULL;

	info("version %s", UDEV_VERSION);

	if (argc < 2 || argc > 3) {
		info("Usage: udevtest <devpath> [subsystem]");
		return 1;
	}

	/* initialize our configuration */
	udev_init_config();

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

	info("looking at '%s'", devpath);

	/* initialize the naming deamon */
	namedev_init();

	if (argc == 3)
		subsystem = argv[2];

	/* fill in values and test_run flag*/
	udev_init_device(&udev, devpath, subsystem);

	/* skip subsystems without "dev", but handle net devices */
	if (udev.type != NET && subsystem_expect_no_dev(udev.subsystem)) {
		info("don't care about '%s' devices", udev.subsystem);
		return 2;
	}

	/* open the device */
	snprintf(path, sizeof(path), "%s%s", sysfs_path, udev.devpath);
	path[sizeof(path)-1] = '\0';
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		info("sysfs_open_class_device_path failed");
		return 1;
	}

	info("opened class_dev->name='%s'", class_dev->name);

	/* simulate node creation with test flag */
	udev.test_run = 1;
	udev_add_device(&udev, class_dev);

	sysfs_close_class_device(class_dev);

	return 0;
}
