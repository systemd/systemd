/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>

#include "udev.h"
#include "udev_rules.h"

static int import_uevent_var(struct udev *udev, const char *devpath)
{
	char path[UTIL_PATH_SIZE];
	static char value[4096]; /* must stay, used with putenv */
	ssize_t size;
	int fd;
	char *key;
	char *next;
	int rc = -1;

	/* read uevent file */
	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, devpath, sizeof(path));
	util_strlcat(path, "/uevent", sizeof(path));
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		goto out;
	value[size] = '\0';

	/* import keys into environment */
	key = value;
	while (key[0] != '\0') {
		next = strchr(key, '\n');
		if (next == NULL)
			goto out;
		next[0] = '\0';
		info(udev, "import into environment: '%s'\n", key);
		putenv(key);
		key = &next[1];
	}
	rc = 0;
out:
	return rc;
}

int udevadm_test(struct udev *udev, int argc, char *argv[])
{
	int force = 0;
	const char *action = "add";
	const char *subsystem = NULL;
	const char *devpath = NULL;
	struct udevice *udevice;
	struct sysfs_device *dev;
	struct udev_rules rules = {};
	int retval;
	int rc = 0;

	static const struct option options[] = {
		{ "action", required_argument, NULL, 'a' },
		{ "subsystem", required_argument, NULL, 's' },
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	info(udev, "version %s\n", VERSION);

	/* export log priority to executed programs */
	if (udev_get_log_priority(udev) > 0) {
		char priority[32];

		sprintf(priority, "%i", udev_get_log_priority(udev));
		setenv("UDEV_LOG", priority, 1);
	}

	while (1) {
		int option;

		option = getopt_long(argc, argv, "a:s:fh", options, NULL);
		if (option == -1)
			break;

		dbg(udev, "option '%c'\n", option);
		switch (option) {
		case 'a':
			action = optarg;
			break;
		case 's':
			subsystem = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'h':
			printf("Usage: udevadm test OPTIONS <devpath>\n"
			       "  --action=<string>     set action string\n"
			       "  --subsystem=<string>  set subsystem string\n"
			       "  --force               don't skip node/link creation\n"
			       "  --help                print this help text\n\n");
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

	printf("This program is for debugging only, it does not run any program,\n"
	       "specified by a RUN key. It may show incorrect results, because\n"
	       "some values may be different, or not available at a simulation run.\n"
	       "\n");

	udev_rules_init(udev, &rules, 0);

	/* remove /sys if given */
	if (strncmp(devpath, udev_get_sys_path(udev), strlen(udev_get_sys_path(udev))) == 0)
		devpath = &devpath[strlen(udev_get_sys_path(udev))];

	dev = sysfs_device_get(udev, devpath);
	if (dev == NULL) {
		fprintf(stderr, "unable to open device '%s'\n", devpath);
		rc = 2;
		goto exit;
	}

	udevice = udev_device_init(udev);
	if (udevice == NULL) {
		fprintf(stderr, "error initializing device\n");
		rc = 3;
		goto exit;
	}

	if (subsystem != NULL)
		util_strlcpy(dev->subsystem, subsystem, sizeof(dev->subsystem));

	/* override built-in sysfs device */
	udevice->dev = dev;
	util_strlcpy(udevice->action, action, sizeof(udevice->action));
	udevice->devt = udev_device_get_devt(udevice);

	/* simulate node creation with test flag */
	if (!force)
		udevice->test_run = 1;

	setenv("DEVPATH", udevice->dev->devpath, 1);
	setenv("SUBSYSTEM", udevice->dev->subsystem, 1);
	setenv("ACTION", udevice->action, 1);
	import_uevent_var(udev, udevice->dev->devpath);

	info(udev, "looking at device '%s' from subsystem '%s'\n", udevice->dev->devpath, udevice->dev->subsystem);
	retval = udev_device_event(&rules, udevice);

	if (udevice->event_timeout >= 0)
		info(udev, "custom event timeout: %i\n", udevice->event_timeout);

	if (retval == 0 && !udevice->ignore_device && udev_get_run(udev)) {
		struct name_entry *name_loop;

		list_for_each_entry(name_loop, &udevice->run_list, node) {
			char program[UTIL_PATH_SIZE];

			util_strlcpy(program, name_loop->name, sizeof(program));
			udev_rules_apply_format(udevice, program, sizeof(program));
			info(udev, "run: '%s'\n", program);
		}
	}
	udev_device_cleanup(udevice);

exit:
	udev_rules_cleanup(&rules);
	return rc;
}
