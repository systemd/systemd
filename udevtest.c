/*
 * udevtest.c
 *
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
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
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>

#include "udev.h"
#include "udev_rules.h"


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
	char *devpath;
	struct udevice *udev;
	struct sysfs_device *dev;
	int retval;
	int rc = 0;

	info("version %s", UDEV_VERSION);

	/* initialize our configuration */
	udev_config_init();
	if (udev_log_priority < LOG_INFO)
		udev_log_priority = LOG_INFO;

	if (argc != 2) {
		info("Usage: udevtest <devpath>");
		return 1;
	}

	sysfs_init();

	/* remove /sys if given */
	if (strncmp(argv[1], sysfs_path, strlen(sysfs_path)) == 0)
		devpath = &argv[1][strlen(sysfs_path)];
	else
		devpath = argv[1];

	udev_rules_init(&rules, 0);

	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		info("unable to open '%s'", devpath);
		rc = 2;
		goto exit;
	}

	udev = udev_device_init();
	if (udev == NULL) {
		info("can't open device");
		rc = 3;
		goto exit;
	}

	/* override built-in sysfs device */
	udev->dev = dev;
	strcpy(udev->action, "add");
	udev->devt = udev_device_get_devt(udev);

	/* simulate node creation with test flag */
	udev->test_run = 1;

	setenv("DEVPATH", udev->dev->devpath, 1);
	setenv("SUBSYSTEM", udev->dev->subsystem, 1);
	setenv("ACTION", "add", 1);

	info("looking at device '%s' from subsystem '%s'", udev->dev->devpath, udev->dev->subsystem);
	retval = udev_device_event(&rules, udev);
	if (retval == 0 && !udev->ignore_device && udev_run) {
		struct name_entry *name_loop;

		list_for_each_entry(name_loop, &udev->run_list, node) {
			char program[PATH_SIZE];

			strlcpy(program, name_loop->name, sizeof(program));
			udev_rules_apply_format(udev, program, sizeof(program));
			info("run: '%s'", program);
		}
	}

exit:
	udev_rules_cleanup(&rules);
	sysfs_cleanup();
	return rc;
}
