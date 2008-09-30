/*
 * Copyright (C) 2008 Kay Sievers <kayi.sievers@vrfy.org>
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
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "udev.h"

static int verbose;
static int dry_run;

static void exec_list(struct udev_enumerate *udev_enumerate, const char *action)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	struct udev_list_entry *entry;

	udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate)) {
		char filename[UTIL_PATH_SIZE];
		int fd;

		if (verbose)
			printf("%s\n", udev_list_entry_get_name(entry));
		if (dry_run)
			continue;
		util_strlcpy(filename, udev_list_entry_get_name(entry), sizeof(filename));
		util_strlcat(filename, "/uevent", sizeof(filename));
		fd = open(filename, O_WRONLY);
		if (fd < 0) {
			dbg(udev, "error on opening %s: %m\n", filename);
			continue;
		}
		if (write(fd, action, strlen(action)) < 0)
			info(udev, "error writing '%s' to '%s': %m\n", action, filename);
		close(fd);
	}
}

static int enumerate_scan_failed(struct udev_enumerate *udev_enumerate)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char base[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	util_strlcpy(base, udev_get_dev_path(udev), sizeof(base));
	util_strlcat(base, "/.udev/failed", sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char syspath[UTIL_PATH_SIZE];
			size_t start;
			struct udev_device *device;

			if (dent->d_name[0] == '.')
				continue;
			start = util_strlcpy(syspath, udev_get_sys_path(udev), sizeof(syspath));
			util_strlcat(syspath, dent->d_name, sizeof(syspath));
			util_path_decode(&syspath[start]);
			device = udev_device_new_from_syspath(udev, syspath);
			if (device == NULL)
				continue;
			udev_enumerate_add_device(udev_enumerate, device);
			udev_device_unref(device);
		}
		closedir(dir);
	}
	return 0;
}

int udevadm_trigger(struct udev *udev, int argc, char *argv[])
{
	static const struct option options[] = {
		{ "verbose", 0, NULL, 'v' },
		{ "dry-run", 0, NULL, 'n' },
		{ "type", 1, NULL, 't' },
		{ "retry-failed", 0, NULL, 'F' },
		{ "action", 1, NULL, 'c' },
		{ "subsystem-match", 1, NULL, 's' },
		{ "subsystem-nomatch", 1, NULL, 'S' },
		{ "attr-match", 1, NULL, 'a' },
		{ "attr-nomatch", 1, NULL, 'A' },
		{ "help", 0, NULL, 'h' },
		{}
	};
	enum {
		TYPE_DEVICES,
		TYPE_SUBSYSTEMS,
		TYPE_FAILED,
	} device_type = TYPE_DEVICES;
	const char *action = "add";
	struct udev_enumerate *udev_enumerate;
	int rc = 0;

	dbg(udev, "version %s\n", VERSION);
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL) {
		rc = 1;
		goto exit;
	}

	while (1) {
		int option;
		char attr[UTIL_PATH_SIZE];
		char *val;

		option = getopt_long(argc, argv, "vnFo:t:hce::s:S:a:A:", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'v':
			verbose = 1;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 't':
			if (strcmp(optarg, "devices") == 0) {
				device_type = TYPE_DEVICES;
			} else if (strcmp(optarg, "subsystems") == 0) {
				device_type = TYPE_SUBSYSTEMS;
			} else if (strcmp(optarg, "failed") == 0) {
				device_type = TYPE_FAILED;
			} else {
				fprintf(stderr, "unknown type --type=%s\n", optarg);
				err(udev, "unknown type --type=%s\n", optarg);
				rc = 2;
				goto exit;
			}
			break;
		case 'F':
			device_type = TYPE_FAILED;
			break;
		case 'c':
			action = optarg;
			break;
		case 's':
			udev_enumerate_add_match_subsystem(udev_enumerate, optarg);
			break;
		case 'S':
			udev_enumerate_add_nomatch_subsystem(udev_enumerate, optarg);
			break;
		case 'a':
			util_strlcpy(attr, optarg, sizeof(attr));
			val = strchr(attr, '=');
			if (val != NULL) {
				val[0] = 0;
				val = &val[1];
			}
			udev_enumerate_add_match_attr(udev_enumerate, attr, val);
			break;
		case 'A':
			util_strlcpy(attr, optarg, sizeof(attr));
			val = strchr(attr, '=');
			if (val != NULL) {
				val[0] = 0;
				val = &val[1];
			}
			udev_enumerate_add_nomatch_attr(udev_enumerate, attr, val);
			break;
		case 'h':
			printf("Usage: udevadm trigger OPTIONS\n"
			       "  --verbose                       print the list of devices while running\n"
			       "  --dry-run                       do not actually trigger the events\n"
			       "  --type=                         type of events to trigger\n"
			       "      devices                       sys devices\n"
			       "      subsystems                    sys subsystems and drivers\n"
			       "      failed                        trigger only the events which have been\n"
			       "                                    marked as failed during a previous run\n"
			       "  --subsystem-match=<subsystem>   trigger devices from a matching subystem\n"
			       "  --subsystem-nomatch=<subsystem> exclude devices from a matching subystem\n"
			       "  --attr-match=<file[=<value>]>   trigger devices with a matching attribute\n"
			       "  --attr-nomatch=<file[=<value>]> exclude devices with a matching attribute\n"
			       "  --help                          print this text\n"
			       "\n");
			goto exit;
		default:
			goto exit;
		}
	}

	switch (device_type) {
	case TYPE_FAILED:
		enumerate_scan_failed(udev_enumerate);
		exec_list(udev_enumerate, action);
		goto exit;
	case TYPE_SUBSYSTEMS:
		udev_enumerate_scan_subsystems(udev_enumerate);
		exec_list(udev_enumerate, action);
		goto exit;
	case TYPE_DEVICES:
		udev_enumerate_scan_devices(udev_enumerate);
		exec_list(udev_enumerate, action);
		goto exit;
	default:
		goto exit;
	}
exit:
	udev_enumerate_unref(udev_enumerate);
	return rc;
}
