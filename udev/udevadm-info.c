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

static void print_all_attributes(struct udev_device *device, const char *key)
{
	DIR *dir;
	struct dirent *dent;

	dir = opendir(udev_device_get_syspath(device));
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			struct stat statbuf;
			char filename[UTIL_PATH_SIZE];
			const char *value;
			size_t len;

			if (dent->d_name[0] == '.')
				continue;

			if (strcmp(dent->d_name, "uevent") == 0)
				continue;
			if (strcmp(dent->d_name, "dev") == 0)
				continue;

			util_strlcpy(filename, udev_device_get_syspath(device), sizeof(filename));
			util_strlcat(filename, "/", sizeof(filename));
			util_strlcat(filename, dent->d_name, sizeof(filename));
			if (lstat(filename, &statbuf) != 0)
				continue;
			if (S_ISLNK(statbuf.st_mode))
				continue;

			value = udev_device_get_attr_value(device, dent->d_name);
			if (value == NULL)
				continue;
			dbg(udev, "attr '%s'='%s'(%zi)\n", dent->d_name, value, len);

			/* skip nonprintable attributes */
			len = strlen(value);
			while (len > 0 && isprint(value[len-1]))
				len--;
			if (len > 0) {
				dbg(info, "attribute value of '%s' non-printable, skip\n", dent->d_name);
				continue;
			}

			printf("    %s{%s}==\"%s\"\n", key, dent->d_name, value);
		}
		closedir(dir);
	}
	printf("\n");
}

static int print_device_chain(struct udev_device *device)
{
	struct udev_device *device_parent;
	const char *str;

	printf("\n"
	       "Udevinfo starts with the device specified by the devpath and then\n"
	       "walks up the chain of parent devices. It prints for every device\n"
	       "found, all possible attributes in the udev rules key format.\n"
	       "A rule to match, can be composed by the attributes of the device\n"
	       "and the attributes from one single parent device.\n"
	       "\n");

	printf("  looking at device '%s':\n", udev_device_get_devpath(device));
	printf("    KERNEL==\"%s\"\n", udev_device_get_sysname(device));
	str = udev_device_get_subsystem(device);
	if (str == NULL)
		str = "";
	printf("    SUBSYSTEM==\"%s\"\n", str);
	str = udev_device_get_driver(device);
	if (str == NULL)
		str = "";
	printf("    DRIVER==\"%s\"\n", str);
	print_all_attributes(device, "ATTR");

	device_parent = device;
	do {
		device_parent = udev_device_get_parent(device_parent);
		if (device_parent == NULL)
			break;
		printf("  looking at parent device '%s':\n", udev_device_get_devpath(device_parent));
		printf("    KERNELS==\"%s\"\n", udev_device_get_sysname(device_parent));
		str = udev_device_get_subsystem(device_parent);
		if (str == NULL)
			str = "";
		printf("    SUBSYSTEMS==\"%s\"\n", str);
		str = udev_device_get_driver(device_parent);
		if (str == NULL)
			str = "";
		printf("    DRIVERS==\"%s\"\n", str);
		print_all_attributes(device_parent, "ATTRS");
	} while (device_parent != NULL);

	return 0;
}

static int print_record_devlinks_cb(struct udev_device *device, const char *value, void *data)
{
	size_t len;

	len = strlen(udev_get_dev_path(udev_device_get_udev(device)));
	printf("S: %s\n", &value[len+1]);
	return 0;
}

static int print_record_properties_cb(struct udev_device *device, const char *key, const char *value, void *data)
{
	printf("E: %s=%s\n", key, value);
	return 0;
}

static void print_record(struct udev_device *device)
{
	size_t len;
	int i;

	printf("P: %s\n", udev_device_get_devpath(device));
	len = strlen(udev_get_dev_path(udev_device_get_udev(device)));
	printf("N: %s\n", &udev_device_get_devname(device)[len+1]);
	i = device_get_devlink_priority(device);
	if (i != 0)
		printf("L: %i\n", i);
	i = device_get_num_fake_partitions(device);
	if (i != 0)
		printf("A:%u\n", i);
	i = device_get_ignore_remove(device);
	if (i != 0)
		printf("R:%u\n", i);
	udev_device_get_devlinks(device, print_record_devlinks_cb, NULL);
	udev_device_get_properties(device, print_record_properties_cb, NULL);
	printf("\n");
}

static int export_all_cb(struct udev_device *device, void *data)
{
	if (udev_device_get_devname(device) != NULL)
		print_record(device);
	return 0;
}

static struct udev_device *lookup_device_by_name(struct udev *udev, const char *name)
{
	struct udev_device *udev_device = NULL;
	LIST_HEAD(name_list);
	int count;
	struct name_entry *device;

	count = udev_db_get_devices_by_name(udev, name, &name_list);
	if (count <= 0)
		goto out;

	info(udev, "found %i devices for '%s'\n", count, name);

	/* select the device that matches */
	list_for_each_entry(device, &name_list, node) {
		struct udevice *udevice_loop;
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;

		udevice_loop = udev_device_init(udev);
		if (udevice_loop == NULL)
			break;
		if (udev_db_get_device(udevice_loop, device->name) != 0)
			goto next;
		info(udev, "found db entry '%s'\n", device->name);
		/* make sure, we don't get a link of a different device */
		util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		util_strlcat(filename, "/", sizeof(filename));
		util_strlcat(filename, name, sizeof(filename));
		if (stat(filename, &statbuf) != 0)
			goto next;
		if (major(udevice_loop->devt) > 0 && udevice_loop->devt != statbuf.st_rdev) {
			info(udev, "skip '%s', dev_t doesn't match\n", udevice_loop->name);
			goto next;
		}
		util_strlcpy(filename, udev_get_sys_path(udev), sizeof(filename));
		util_strlcat(filename,  udevice_loop->dev->devpath, sizeof(filename));
		udev_device = udev_device_new_from_syspath(udev, filename);
		udev_device_cleanup(udevice_loop);
		break;
next:
		udev_device_cleanup(udevice_loop);
	}
out:
	name_list_cleanup(udev, &name_list);
	return udev_device;
}

static int add_devlink_cb(struct udev_device *device, const char *value, void *data)
{
	char **links = data;

	if (*links == NULL) {
		*links = strdup(value);
	} else {
		char *str;

		asprintf(&str, "%s %s", *links, value);
		free(*links);
		*links = str;
	}
	return 0;
}

static int add_devlink_noroot_cb(struct udev_device *device, const char *value, void *data)
{
	size_t len;

	len = strlen(udev_get_dev_path(udev_device_get_udev(device)));
	value = &value[len+1];
	return add_devlink_cb(device, value, data);
}

static int print_property_cb(struct udev_device *device, const char *key, const char *value, void *data)
{
	printf("%s=%s\n", key, value);
	return 0;
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
	struct udev_device *device = NULL;
	int root = 0;
	int export = 0;
	const char *export_prefix = NULL;
	char path[UTIL_PATH_SIZE];
	char name[UTIL_PATH_SIZE];
	char *links;
	int rc = 0;

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

	while (1) {
		int option;

		option = getopt_long(argc, argv, "aed:n:p:q:rxPVh", options, NULL);
		if (option == -1)
			break;

		dbg(udev, "option '%c'\n", option);
		switch (option) {
		case 'n':
			if (device != NULL) {
				fprintf(stderr, "device already specified\n");
				rc = 2;
				goto exit;
			}
			/* remove /dev if given */
			if (strncmp(optarg, udev_get_dev_path(udev), strlen(udev_get_dev_path(udev))) == 0)
				util_strlcpy(name, &optarg[strlen(udev_get_dev_path(udev))+1], sizeof(name));
			else
				util_strlcpy(name, optarg, sizeof(name));
			util_remove_trailing_chars(name, '/');
			device = lookup_device_by_name(udev, name);
			break;
		case 'p':
			if (device != NULL) {
				fprintf(stderr, "device already specified\n");
				rc = 2;
				goto exit;
			}
			/* add /sys if needed */
			if (strncmp(optarg, udev_get_sys_path(udev), strlen(udev_get_sys_path(udev))) != 0) {
				util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
				util_strlcat(path, optarg, sizeof(path));
			} else {
				util_strlcpy(path, optarg, sizeof(path));
			}
			util_remove_trailing_chars(path, '/');
			device = udev_device_new_from_syspath(udev, path);
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
			util_strlcpy(name, optarg, sizeof(name));
			break;
		case 'a':
			action = ACTION_ATTRIBUTE_WALK;
			break;
		case 'e':
			udev_enumerate_devices(udev, NULL, export_all_cb, NULL);
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

	switch (action) {
	case ACTION_QUERY:
		if (device == NULL) {
			fprintf(stderr, "query needs a valid device specified by --path= or --name=\n");
			rc = 4;
			goto exit;
		}

		switch(query) {
		case QUERY_NAME:
			if (root) {
				printf("%s\n", udev_device_get_devname(device));
			} else {
				size_t len;

				len = strlen(udev_get_dev_path(udev));
				printf("%s\n", &udev_device_get_devname(device)[len+1]);
			}
			break;
		case QUERY_SYMLINK:
			links = NULL;
			if (root)
				udev_device_get_devlinks(device, add_devlink_cb, &links);
			else
				udev_device_get_devlinks(device, add_devlink_noroot_cb, &links);
			printf("%s\n", links);
			free(links);
			break;
		case QUERY_PATH:
			printf("%s\n", udev_device_get_devpath(device));
			goto exit;
		case QUERY_ENV:
			udev_device_get_properties(device, print_property_cb, NULL);
			break;
		case QUERY_ALL:
			print_record(device);
			break;
		default:
			fprintf(stderr, "unknown query type\n");
			break;
		}
		break;
	case ACTION_ATTRIBUTE_WALK:
		if (device == NULL) {
			fprintf(stderr, "query needs a valid device specified by --path= or --name=\n");
			rc = 5;
			goto exit;
		}
		print_device_chain(device);
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
	udev_device_unref(device);
	return rc;
}
