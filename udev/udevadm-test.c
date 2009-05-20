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

int udevadm_test(struct udev *udev, int argc, char *argv[])
{
	char filename[UTIL_PATH_SIZE];
	const char *action = "add";
	const char *syspath = NULL;
	struct udev_event *event;
	struct udev_device *dev;
	struct udev_rules *rules = NULL;
	int err;
	int rc = 0;

	static const struct option options[] = {
		{ "action", required_argument, NULL, 'a' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	info(udev, "version %s\n", VERSION);

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
		case 'h':
			printf("Usage: udevadm test OPTIONS <syspath>\n"
			       "  --action=<string>     set action string\n"
			       "  --help\n\n");
			exit(0);
		default:
			exit(1);
		}
	}
	syspath = argv[optind];

	if (syspath == NULL) {
		fprintf(stderr, "syspath parameter missing\n");
		rc = 1;
		goto exit;
	}

	printf("This program is for debugging only, it does not run any program,\n"
	       "specified by a RUN key. It may show incorrect results, because\n"
	       "some values may be different, or not available at a simulation run.\n"
	       "\n");

	rules = udev_rules_new(udev, 1);
	if (rules == NULL) {
		fprintf(stderr, "error reading rules\n");
		rc = 1;
		goto exit;
	}

	/* add /sys if needed */
	if (strncmp(syspath, udev_get_sys_path(udev), strlen(udev_get_sys_path(udev))) != 0)
		util_strscpyl(filename, sizeof(filename), udev_get_sys_path(udev), syspath, NULL);
	else
		util_strscpy(filename, sizeof(filename), syspath);
	util_remove_trailing_chars(filename, '/');

	dev = udev_device_new_from_syspath(udev, filename);
	if (dev == NULL) {
		fprintf(stderr, "unable to open device '%s'\n", filename);
		rc = 2;
		goto exit;
	}

	/* skip reading of db, but read kernel parameters */
	udev_device_set_info_loaded(dev);
	udev_device_read_uevent_file(dev);

	udev_device_set_action(dev, action);
	event = udev_event_new(dev);
	err = udev_event_execute_rules(event, rules);

	if (udev_device_get_event_timeout(dev) >= 0)
		info(udev, "custom event timeout: %i\n", udev_device_get_event_timeout(dev));

	if (err == 0 && !event->ignore_device && udev_get_run(udev)) {
		struct udev_list_entry *entry;

		udev_list_entry_foreach(entry, udev_list_get_entry(&event->run_list)) {
			char program[UTIL_PATH_SIZE];

			udev_event_apply_format(event, udev_list_entry_get_name(entry), program, sizeof(program));
			info(udev, "run: '%s'\n", program);
		}
	}
	udev_event_unref(event);
	udev_device_unref(dev);
exit:
	udev_rules_unref(rules);
	return rc;
}
