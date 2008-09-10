/*
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

static void print_all_attributes(struct udev *udev, const char *devpath, const char *key)
{
	char path[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, devpath, sizeof(path));

	dir = opendir(path);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			struct stat statbuf;
			char filename[PATH_SIZE];
			char *attr_value;
			char value[NAME_SIZE];
			size_t len;

			if (dent->d_name[0] == '.')
				continue;

			if (strcmp(dent->d_name, "uevent") == 0)
				continue;
			if (strcmp(dent->d_name, "dev") == 0)
				continue;

			strlcpy(filename, path, sizeof(filename));
			strlcat(filename, "/", sizeof(filename));
			strlcat(filename, dent->d_name, sizeof(filename));
			if (lstat(filename, &statbuf) != 0)
				continue;
			if (S_ISLNK(statbuf.st_mode))
				continue;

			attr_value = sysfs_attr_get_value(udev, devpath, dent->d_name);
			if (attr_value == NULL)
				continue;
			len = strlcpy(value, attr_value, sizeof(value));
			if(len >= sizeof(value))
				len = sizeof(value) - 1;
			dbg(udev, "attr '%s'='%s'(%zi)\n", dent->d_name, value, len);

			/* skip nonprintable attributes */
			while (len && isprint(value[len-1]))
				len--;
			if (len) {
				dbg(udev, "attribute value of '%s' non-printable, skip\n", dent->d_name);
				continue;
			}

			printf("    %s{%s}==\"%s\"\n", key, dent->d_name, value);
		}
	}
	printf("\n");
}

static int print_device_chain(struct udev *udev, const char *devpath)
{
	struct sysfs_device *dev;

	dev = sysfs_device_get(udev, devpath);
	if (dev == NULL)
		return -1;

	printf("\n"
	       "Udevinfo starts with the device specified by the devpath and then\n"
	       "walks up the chain of parent devices. It prints for every device\n"
	       "found, all possible attributes in the udev rules key format.\n"
	       "A rule to match, can be composed by the attributes of the device\n"
	       "and the attributes from one single parent device.\n"
	       "\n");

	printf("  looking at device '%s':\n", dev->devpath);
	printf("    KERNEL==\"%s\"\n", dev->kernel);
	printf("    SUBSYSTEM==\"%s\"\n", dev->subsystem);
	printf("    DRIVER==\"%s\"\n", dev->driver);
	print_all_attributes(udev, dev->devpath, "ATTR");

	/* walk up the chain of devices */
	while (1) {
		dev = sysfs_device_get_parent(udev, dev);
		if (dev == NULL)
			break;
		printf("  looking at parent device '%s':\n", dev->devpath);
		printf("    KERNELS==\"%s\"\n", dev->kernel);
		printf("    SUBSYSTEMS==\"%s\"\n", dev->subsystem);
		printf("    DRIVERS==\"%s\"\n", dev->driver);

		print_all_attributes(udev, dev->devpath, "ATTRS");
	}

	return 0;
}

static void print_record(struct udevice *udevice)
{
	struct name_entry *name_loop;

	printf("P: %s\n", udevice->dev->devpath);
	printf("N: %s\n", udevice->name);
	list_for_each_entry(name_loop, &udevice->symlink_list, node)
		printf("S: %s\n", name_loop->name);
	if (udevice->link_priority != 0)
		printf("L: %i\n", udevice->link_priority);
	if (udevice->partitions != 0)
		printf("A:%u\n", udevice->partitions);
	if (udevice->ignore_remove)
		printf("R:%u\n", udevice->ignore_remove);
	list_for_each_entry(name_loop, &udevice->env_list, node)
		printf("E: %s\n", name_loop->name);
}

static void export_db(struct udev *udev)
{
	LIST_HEAD(name_list);
	struct name_entry *name_loop;

	udev_db_get_all_entries(udev, &name_list);
	list_for_each_entry(name_loop, &name_list, node) {
		struct udevice *udevice_db;

		udevice_db = udev_device_init(udev);
		if (udevice_db == NULL)
			continue;
		if (udev_db_get_device(udevice_db, name_loop->name) == 0)
			print_record(udevice_db);
			printf("\n");
		udev_device_cleanup(udevice_db);
	}
	name_list_cleanup(udev, &name_list);
}

static int lookup_device_by_name(struct udev *udev, struct udevice **udevice, const char *name)
{
	LIST_HEAD(name_list);
	int count;
	struct name_entry *device;
	int rc  = -1;

	count = udev_db_get_devices_by_name(udev, name, &name_list);
	if (count <= 0)
		goto out;

	info(udev, "found %i devices for '%s'\n", count, name);

	/* select the device that seems to match */
	list_for_each_entry(device, &name_list, node) {
		struct udevice *udevice_loop;
		char filename[PATH_SIZE];
		struct stat statbuf;

		udevice_loop = udev_device_init(udev);
		if (udevice_loop == NULL)
			break;
		if (udev_db_get_device(udevice_loop, device->name) != 0)
			goto next;
		info(udev, "found db entry '%s'\n", device->name);

		/* make sure, we don't get a link of a different device */
		strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		strlcat(filename, "/", sizeof(filename));
		strlcat(filename, name, sizeof(filename));
		if (stat(filename, &statbuf) != 0)
			goto next;
		if (major(udevice_loop->devt) > 0 && udevice_loop->devt != statbuf.st_rdev) {
			info(udev, "skip '%s', dev_t doesn't match\n", udevice_loop->name);
			goto next;
		}
		rc = 0;
		*udevice = udevice_loop;
		break;
next:
		udev_device_cleanup(udevice_loop);
	}
out:
	name_list_cleanup(udev, &name_list);
	return rc;
}

static int stat_device(const char *name, int export, const char *prefix)
{
	struct stat statbuf;

	if (stat(name, &statbuf) != 0)
		return -1;

	if (export) {
		if (prefix == NULL)
			prefix = "INFO_";
		printf("%sMAJOR=%d\n"
		       "%sMINOR=%d\n",
		       prefix, major(statbuf.st_dev),
		       prefix, minor(statbuf.st_dev));
	} else
		printf("%d:%d\n", major(statbuf.st_dev), minor(statbuf.st_dev));
	return 0;
}

int udevadm_info(struct udev *udev, int argc, char *argv[])
{
	struct udevice *udevice = NULL;
	int root = 0;
	int export = 0;
	const char *export_prefix = NULL;

	static const struct option options[] = {
		{ "name", 1, NULL, 'n' },
		{ "path", 1, NULL, 'p' },
		{ "query", 1, NULL, 'q' },
		{ "attribute-walk", 0, NULL, 'a' },
		{ "export-db", 0, NULL, 'e' },
		{ "root", 0, NULL, 'r' },
		{ "device-id-of-file", 1, NULL, 'd' },
		{ "export", 0, NULL, 'x' },
		{ "export-prefix", 1, NULL, 'P' },
		{ "version", 0, NULL, 1 }, /* -V outputs braindead format */
		{ "help", 0, NULL, 'h' },
		{}
	};

	enum action_type {
		ACTION_NONE,
		ACTION_QUERY,
		ACTION_ATTRIBUTE_WALK,
		ACTION_ROOT,
		ACTION_DEVICE_ID_FILE,
	} action = ACTION_NONE;

	enum query_type {
		QUERY_NONE,
		QUERY_NAME,
		QUERY_PATH,
		QUERY_SYMLINK,
		QUERY_ENV,
		QUERY_ALL,
	} query = QUERY_NONE;

	char path[PATH_SIZE] = "";
	char name[PATH_SIZE] = "";
	struct name_entry *name_loop;
	int rc = 0;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "aed:n:p:q:rxPVh", options, NULL);
		if (option == -1)
			break;

		dbg(udev, "option '%c'\n", option);
		switch (option) {
		case 'n':
			/* remove /dev if given */
			if (strncmp(optarg, udev_get_dev_path(udev), strlen(udev_get_dev_path(udev))) == 0)
				strlcpy(name, &optarg[strlen(udev_get_dev_path(udev))+1], sizeof(name));
			else
				strlcpy(name, optarg, sizeof(name));
			util_remove_trailing_chars(name, '/');
			dbg(udev, "name: %s\n", name);
			break;
		case 'p':
			/* remove /sys if given */
			if (strncmp(optarg, udev_get_sys_path(udev), strlen(udev_get_sys_path(udev))) == 0)
				strlcpy(path, &optarg[strlen(udev_get_sys_path(udev))], sizeof(path));
			else
				strlcpy(path, optarg, sizeof(path));
			util_remove_trailing_chars(path, '/');

			/* possibly resolve to real devpath */
			if (sysfs_resolve_link(udev, path, sizeof(path)) != 0) {
				char temp[PATH_SIZE];
				char *pos;

				/* also check if the parent is a link */
				strlcpy(temp, path, sizeof(temp));
				pos = strrchr(temp, '/');
				if (pos != 0) {
					char tail[PATH_SIZE];

					strlcpy(tail, pos, sizeof(tail));
					pos[0] = '\0';
					if (sysfs_resolve_link(udev, temp, sizeof(temp)) == 0) {
						strlcpy(path, temp, sizeof(path));
						strlcat(path, tail, sizeof(path));
					}
				}
			}
			dbg(udev, "path: %s\n", path);
			break;
		case 'q':
			action = ACTION_QUERY;
			if (strcmp(optarg, "name") == 0) {
				query = QUERY_NAME;
				break;
			}
			if (strcmp(optarg, "symlink") == 0) {
				query = QUERY_SYMLINK;
				break;
			}
			if (strcmp(optarg, "path") == 0) {
				query = QUERY_PATH;
				break;
			}
			if (strcmp(optarg, "env") == 0) {
				query = QUERY_ENV;
				break;
			}
			if (strcmp(optarg, "all") == 0) {
				query = QUERY_ALL;
				break;
			}
			fprintf(stderr, "unknown query type\n");
			rc = 2;
			goto exit;
		case 'r':
			if (action == ACTION_NONE)
				action = ACTION_ROOT;
			root = 1;
			break;
		case 'd':
			action = ACTION_DEVICE_ID_FILE;
			strlcpy(name, optarg, sizeof(name));
			break;
		case 'a':
			action = ACTION_ATTRIBUTE_WALK;
			break;
		case 'e':
			export_db(udev);
			goto exit;
		case 'x':
			export = 1;
			break;
		case 'P':
			export_prefix = optarg;
			break;
		case 1:
			printf("%s\n", VERSION);
			goto exit;
		case 'V':
			printf("udevinfo, version %s\n", VERSION);
			goto exit;
		case 'h':
			printf("Usage: udevadm info OPTIONS\n"
			       "  --query=<type>             query database for the specified value:\n"
			       "      name                     name of device node\n"
			       "      symlink                  pointing to node\n"
			       "      path                     sysfs device path\n"
			       "      env                      the device related imported environment\n"
			       "      all                      all values\n"
			       "  --path=<devpath>           sysfs device path used for query or chain\n"
			       "  --name=<name>              node or symlink name used for query\n"
			       "  --root                     prepend to query result or print udev_root\n"
			       "  --attribute-walk           print all key matches while walking along chain\n"
			       "                             of parent devices\n"
			       "  --device-id-of-file=<file> print major/minor of underlying device\n"
			       "  --export-db                export the content of the udev database\n"
			       "  --help                     print this text\n"
			       "\n");
			goto exit;
		default:
			goto exit;
		}
	}

	/* run action */
	switch (action) {
	case ACTION_QUERY:
		/* needs devpath or node/symlink name for query */
		if (path[0] != '\0') {
			udevice = udev_device_init(udev);
			if (udevice == NULL) {
				rc = 1;
				goto exit;
			}
			if (udev_db_get_device(udevice, path) != 0) {
				fprintf(stderr, "no record for '%s' in database\n", path);
				rc = 3;
				goto exit;
			}
		} else if (name[0] != '\0') {
			if (lookup_device_by_name(udev, &udevice, name) != 0) {
				fprintf(stderr, "node name not found\n");
				rc = 4;
				goto exit;
			}
		} else {
			fprintf(stderr, "query needs --path or node --name specified\n");
			rc = 4;
			goto exit;
		}

		switch(query) {
		case QUERY_NAME:
			if (root)
				printf("%s/%s\n", udev_get_dev_path(udev), udevice->name);
			else
				printf("%s\n", udevice->name);
			break;
		case QUERY_SYMLINK:
			list_for_each_entry(name_loop, &udevice->symlink_list, node) {
				char c = name_loop->node.next != &udevice->symlink_list ? ' ' : '\n';

				if (root)
					printf("%s/%s%c", udev_get_dev_path(udev), name_loop->name, c);
				else
					printf("%s%c", name_loop->name, c);
			}
			break;
		case QUERY_PATH:
			printf("%s\n", udevice->dev->devpath);
			goto exit;
		case QUERY_ENV:
			list_for_each_entry(name_loop, &udevice->env_list, node)
				printf("%s\n", name_loop->name);
			break;
		case QUERY_ALL:
			print_record(udevice);
			break;
		default:
			fprintf(stderr, "unknown query type\n");
			break;
		}
		break;
	case ACTION_ATTRIBUTE_WALK:
		if (path[0] != '\0') {
			if (print_device_chain(udev, path) != 0) {
				fprintf(stderr, "no valid sysfs device found\n");
				rc = 4;
				goto exit;
			}
		} else if (name[0] != '\0') {
			if (lookup_device_by_name(udev, &udevice, name) != 0) {
				fprintf(stderr, "node name not found\n");
				rc = 4;
				goto exit;
			}
			if (print_device_chain(udev, udevice->dev->devpath) != 0) {
				fprintf(stderr, "no valid sysfs device found\n");
				rc = 4;
				goto exit;
			}
		} else {
			fprintf(stderr, "attribute walk needs --path or node --name specified\n");
			rc = 5;
			goto exit;
		}
		break;
	case ACTION_DEVICE_ID_FILE:
		if (stat_device(name, export, export_prefix) != 0)
			rc = 6;
		break;
	case ACTION_ROOT:
		printf("%s\n", udev_get_dev_path(udev));
		break;
	default:
		fprintf(stderr, "missing option\n");
		rc = 1;
		break;
	}

exit:
	udev_device_cleanup(udevice);
	return rc;
}
