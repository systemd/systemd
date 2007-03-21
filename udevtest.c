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
#include <getopt.h>

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
	int force = 0;
	char *action = "add";
	struct udev_rules rules = {};
	char *devpath = NULL;
	struct udevice *udev;
	struct sysfs_device *dev;
	int retval;
	int rc = 0;

	static const struct option options[] = {
		{ "action", 1, NULL, 'a' },
		{ "force", 0, NULL, 'f' },
		{ "help", 0, NULL, 'h' },
		{}
	};

	info("version %s", UDEV_VERSION);
	udev_config_init();
	if (udev_log_priority < LOG_INFO) {
		char priority[32];

		udev_log_priority = LOG_INFO;
		sprintf(priority, "%i", udev_log_priority);
		setenv("UDEV_LOG", priority, 1);
	}

	while (1) {
		int option;

		option = getopt_long(argc, argv, "a:fh", options, NULL);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'a':
			action = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'h':
			printf("Usage: udevtest [--action=<string>] [--force] [--help] <devpath>\n"
			       "  --action=<string>   set action string\n"
			       "  --force             don't skip node/link creation\n"
			       "  --help              print this help text\n\n");
			exit(0);
		default:
			exit(1);
		}
	}
	devpath = argv[optind];

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

	udev = udev_device_init(NULL);
	if (udev == NULL) {
		fprintf(stderr, "error initializing device\n");
		rc = 3;
		goto exit;
	}

	/* override built-in sysfs device */
	udev->dev = dev;
	strcpy(udev->action, action);
	udev->devt = udev_device_get_devt(udev);

	/* simulate node creation with test flag */
	if (!force)
		udev->test_run = 1;

	setenv("DEVPATH", udev->dev->devpath, 1);
	setenv("SUBSYSTEM", udev->dev->subsystem, 1);
	setenv("ACTION", "add", 1);

	printf("This program is for debugging only, it does not run any program,\n"
	       "specified by a RUN key. It may show incorrect results, if rules\n"
	       "match against subsystem specfic kernel event variables.\n"
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
