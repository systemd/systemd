/*
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
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"


#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list	args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void print_all_attributes(const char *devpath, const char *key)
{
	char path[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(path, sysfs_path, sizeof(path));
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

			strlcpy(filename, path, sizeof(filename));
			strlcat(filename, "/", sizeof(filename));
			strlcat(filename, dent->d_name, sizeof(filename));
			if (lstat(filename, &statbuf) != 0)
				continue;
			if (S_ISLNK(statbuf.st_mode))
				continue;

			attr_value = sysfs_attr_get_value(devpath, dent->d_name);
			if (attr_value == NULL)
				continue;
			len = strlcpy(value, attr_value, sizeof(value));
			dbg("attr '%s'='%s'(%zi)", dent->d_name, value, len);

			/* remove trailing newlines */
			while (len && value[len-1] == '\n')
				value[--len] = '\0';

			/* skip nonprintable attributes */
			while (len && isprint(value[len-1]))
				len--;
			if (len) {
				dbg("attribute value of '%s' non-printable, skip", dent->d_name);
				continue;
			}

			replace_untrusted_chars(value);
			printf("    %s{%s}==\"%s\"\n", key, dent->d_name, value);
		}
	}
	printf("\n");
}

static int print_device_chain(const char *devpath)
{
	struct sysfs_device *dev;

	dev = sysfs_device_get(devpath);
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
	print_all_attributes(dev->devpath, "ATTR");

	/* walk up the chain of devices */
	while (1) {
		dev = sysfs_device_get_parent(dev);
		if (dev == NULL)
			break;
		printf("  looking at parent device '%s':\n", dev->devpath);
		printf("    KERNELS==\"%s\"\n", dev->kernel);
		printf("    SUBSYSTEMS==\"%s\"\n", dev->subsystem);
		printf("    DRIVERS==\"%s\"\n", dev->driver);

		print_all_attributes(dev->devpath, "ATTRS");
	}

	return 0;
}

static void print_record(struct udevice *udev)
{
	struct name_entry *name_loop;

	printf("P: %s\n", udev->dev->devpath);
	printf("N: %s\n", udev->name);
	list_for_each_entry(name_loop, &udev->symlink_list, node)
		printf("S: %s\n", name_loop->name);
	list_for_each_entry(name_loop, &udev->env_list, node)
		printf("E: %s\n", name_loop->name);
}

static void export_name_devpath(struct udevice *udev) {
	printf("%s=%s/%s\n", udev->dev->devpath, udev_root, udev->name);
}

static void export_record(struct udevice *udev) {
	print_record(udev);
	printf("\n");
}

static void export_db(void fnct(struct udevice *udev)) {
	LIST_HEAD(name_list);
	struct name_entry *name_loop;

	udev_db_get_all_entries(&name_list);
	list_for_each_entry(name_loop, &name_list, node) {
		struct udevice *udev_db;

		udev_db = udev_device_init();
		if (udev_db == NULL)
			continue;
		if (udev_db_get_device(udev_db, name_loop->name) == 0)
			fnct(udev_db);
		udev_device_cleanup(udev_db);
	}
	name_list_cleanup(&name_list);
}

int main(int argc, char *argv[], char *envp[])
{
	int option;
	struct udevice *udev;
	int root = 0;

	static const struct option options[] = {
		{ "name", 1, NULL, 'n' },
		{ "path", 1, NULL, 'p' },
		{ "query", 1, NULL, 'q' },
		{ "attribute-walk", 0, NULL, 'a' },
		{ "export-db", 0, NULL, 'e' },
		{ "root", 0, NULL, 'r' },
		{ "version", 0, NULL, 'V' },
		{ "help", 0, NULL, 'h' },
		{}
	};

	enum action_type {
		ACTION_NONE,
		ACTION_QUERY,
		ACTION_ATTRIBUTE_WALK,
		ACTION_ROOT,
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

	logging_init("udevinfo");
	udev_config_init();
	sysfs_init();

	udev = udev_device_init();
	if (udev == NULL) {
		rc = 1;
		goto exit;
	}

	/* get command line options */
	while (1) {
		option = getopt_long(argc, argv, "aden:p:q:rVh", options, NULL);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'n':
			/* remove /dev if given */
			if (strncmp(optarg, udev_root, strlen(udev_root)) == 0)
				strlcpy(name, &optarg[strlen(udev_root)+1], sizeof(name));
			else
				strlcpy(name, optarg, sizeof(name));
			dbg("name: %s\n", name);
			break;
		case 'p':
			/* remove /sys if given */
			if (strncmp(optarg, sysfs_path, strlen(sysfs_path)) == 0)
				strlcpy(path, &optarg[strlen(sysfs_path)], sizeof(path));
			else
				strlcpy(path, optarg, sizeof(path));
			dbg("path: %s\n", path);
			break;
		case 'q':
			dbg("udev query: %s\n", optarg);
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
		case 'a':
			action = ACTION_ATTRIBUTE_WALK;
			break;
		case 'd':
			export_db(export_name_devpath);
			goto exit;
		case 'e':
			export_db(export_record);
			goto exit;
		case 'V':
			printf("udevinfo, version %s\n", UDEV_VERSION);
			goto exit;
		case 'h':
			printf("Usage: udevinfo OPTIONS\n"
			       "  --query=<type>    query database for the specified value:\n"
			       "    name            name of device node\n"
			       "    symlink         pointing to node\n"
			       "    path            sysfs device path\n"
			       "    env             the device related imported environment\n"
			       "    all             all values\n"
			       "\n"
			       "  --path=<devpath>  sysfs device path used for query or chain\n"
			       "  --name=<name>     node or symlink name used for query\n"
			       "\n"
			       "  --root            prepend to query result or print udev_root\n"
			       "  --attribute-walk  print all SYSFS_attributes along the device chain\n"
			       "  --export-db       export the content of the udev database\n"
			       "  --help            print this text\n"
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
			if (udev_db_get_device(udev, path) != 0) {
				fprintf(stderr, "no record for '%s' in database\n", path);
				rc = 3;
				goto exit;
			}
		} else if (name[0] != '\0') {
			char devpath[PATH_SIZE];

			if (udev_db_lookup_name(name, devpath, sizeof(devpath)) != 0) {
				fprintf(stderr, "node name not found\n");
				rc = 4;
				goto exit;
			}
			udev_db_get_device(udev, devpath);
		} else {
			fprintf(stderr, "query needs --path or node --name specified\n");
			rc = 4;
			goto exit;
		}

		switch(query) {
		case QUERY_NAME:
			if (root)
				printf("%s/%s\n", udev_root, udev->name);
			else
				printf("%s\n", udev->name);
			break;
		case QUERY_SYMLINK:
			if (list_empty(&udev->symlink_list))
				goto exit;
			if (root)
				list_for_each_entry(name_loop, &udev->symlink_list, node)
					printf("%s/%s ", udev_root, name_loop->name);
			else
				list_for_each_entry(name_loop, &udev->symlink_list, node)
					printf("%s ", name_loop->name);
			printf("\n");
			break;
		case QUERY_PATH:
			printf("%s\n", udev->dev->devpath);
			goto exit;
		case QUERY_ENV:
			list_for_each_entry(name_loop, &udev->env_list, node)
				printf("%s\n", name_loop->name);
			break;
		case QUERY_ALL:
			print_record(udev);
			break;
		default:
			fprintf(stderr, "unknown query type\n");
			break;
		}
		break;
	case ACTION_ATTRIBUTE_WALK:
		if (path[0] != '\0') {
			if (print_device_chain(path) != 0) {
				fprintf(stderr, "device not found\n");
				rc = 4;
				goto exit;
			}
		} else if (name[0] != '\0') {
			char devpath[PATH_SIZE];

			if (udev_db_lookup_name(name, devpath, sizeof(devpath)) != 0) {
				fprintf(stderr, "node name not found\n");
				rc = 4;
				goto exit;
			}
			if (print_device_chain(devpath) != 0) {
				fprintf(stderr, "device not found\n");
				rc = 4;
				goto exit;
			}
		} else {
			fprintf(stderr, "attribute walk needs --path or node --name specified\n");
			rc = 5;
			goto exit;
		}
		break;
	case ACTION_ROOT:
		printf("%s\n", udev_root);
		break;
	default:
		fprintf(stderr, "missing option\n");
		rc = 1;
		break;
	}

exit:
	udev_device_cleanup(udev);
	sysfs_cleanup();
	logging_close();
	return rc;
}
