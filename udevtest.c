/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
	struct udev_rules rules = {};
	char *devpath = NULL;
	struct udevice *udev;
	struct sysfs_device *dev;
	int i;
	int retval;
	int rc = 0;

	info("version %s", UDEV_VERSION);
	udev_config_init();
	if (udev_log_priority < LOG_INFO)
		udev_log_priority = LOG_INFO;

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
			printf("Usage: udevtest [--help] <devpath>\n");
			goto exit;
		} else
			devpath = arg;
	}

	if (devpath == NULL) {
		fprintf(stderr, "devpath parameter missing\n");
		rc = 1;
		goto exit;
	}

	sysfs_init();
	udev_rules_init(&rules, 0);

	/* remove /sys if given */
	if (strncmp(devpath, sysfs_path, strlen(sysfs_path)) == 0)
		devpath = &devpath[strlen(sysfs_path)];

	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		fprintf(stderr, "unable to open device '%s'\n", devpath);
		rc = 2;
		goto exit;
	}

	udev = udev_device_init();
	if (udev == NULL) {
		fprintf(stderr, "error initializing device\n");
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

	printf("This program is for debugging only, it does not create any node,\n"
	       "or run any program specified by a RUN key. It may show incorrect results,\n"
	       "if rules match against subsystem specfic kernel event variables.\n"
	       "\n");

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
