/*
 * udevinfo - fetches attributes for a device
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "udev_db.h"
#include "logging.h"


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

static void print_all_attributes(struct dlist *attr_list)
{
	struct sysfs_attribute *attr;
	char value[VALUE_SIZE];
	int len;

	dlist_for_each_data(attr_list, attr, struct sysfs_attribute) {
		if (attr->value != NULL) {
			strlcpy(value, attr->value, sizeof(value));
			len = strlen(value);
			if (len == 0)
				continue;

			/* remove trailing newline */
			if (value[len-1] == '\n') {
				value[len-1] = '\0';
				len--;
			}

			/* skip nonprintable values */
			while (len) {
				if (isprint(value[len-1]) == 0)
					break;
				len--;
			}
			if (len == 0)
				printf("    SYSFS{%s}==\"%s\"\n", attr->name, value);
		}
	}
	printf("\n");
}

static int print_record(struct udevice *udev)
{
	struct name_entry *name_loop;

	printf("P: %s\n", udev->devpath);
	printf("N: %s\n", udev->name);
	list_for_each_entry(name_loop, &udev->symlink_list, node)
		printf("S: %s\n", name_loop->name);

	return 0;
}

enum query_type {
	NONE,
	NAME,
	PATH,
	SYMLINK,
	ALL,
};

static int print_device_chain(const char *path)
{
	struct sysfs_class_device *class_dev;
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_attribute *attr;
	struct sysfs_device *sysfs_dev;
	struct sysfs_device *sysfs_dev_parent;
	struct dlist *attr_list;
	int retval = 0;

	/*  get the class dev */
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		fprintf(stderr, "couldn't get the class device\n");
		return -1;
	}

	printf("\nudevinfo starts with the device the node belongs to and then walks up the\n"
	       "device chain, to print for every device found, all possibly useful attributes\n"
	       "in the udev key format.\n"
	       "Only attributes within one device section may be used together in one rule,\n"
	       "to match the device for which the node will be created.\n"
	       "\n");

	/* look for the 'dev' file */
	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr != NULL)
		printf("device '%s' has major:minor %s", class_dev->path, attr->value);

	/* open sysfs class device directory and print all attributes */
	printf("  looking at class device '%s':\n", class_dev->path);
	printf("    SUBSYSTEM==\"%s\"\n", class_dev->classname);

	attr_list = sysfs_get_classdev_attributes(class_dev);
	if (attr_list == NULL) {
		fprintf(stderr, "couldn't open class device directory\n");
		retval = -1;
		goto exit;
	}
	print_all_attributes(attr_list);

	/* get the device link (if parent exists look here) */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent != NULL) 
		sysfs_dev = sysfs_get_classdev_device(class_dev_parent);
	else 
		sysfs_dev = sysfs_get_classdev_device(class_dev);
	
	if (sysfs_dev != NULL)
		printf("follow the class device's \"device\"\n");

	/* look the device chain upwards */
	while (sysfs_dev != NULL) {
		attr_list = sysfs_get_device_attributes(sysfs_dev);
		if (attr_list == NULL) {
			fprintf(stderr, "couldn't open device directory\n");
			retval = -1;
			goto exit;
		}

		printf("  looking at the device chain at '%s':\n", sysfs_dev->path);
		printf("    BUS==\"%s\"\n", sysfs_dev->bus);
		printf("    ID==\"%s\"\n", sysfs_dev->bus_id);
		printf("    DRIVER==\"%s\"\n", sysfs_dev->driver_name);

		/* open sysfs device directory and print all attributes */
		print_all_attributes(attr_list);

		sysfs_dev_parent = sysfs_get_device_parent(sysfs_dev);
		if (sysfs_dev_parent == NULL)
			break;

		sysfs_dev = sysfs_dev_parent;
	}

exit:
	sysfs_close_class_device(class_dev);
	return retval;
}

static int print_dump(const char *devpath, const char *name) {
	printf("%s=%s/%s\n", devpath, udev_root, name);
	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	static const char short_options[] = "adn:p:q:rVh";
	int option;
	struct udevice udev;
	int root = 0;
	int attributes = 0;
	enum query_type query = NONE;
	char path[PATH_SIZE] = "";
	char name[PATH_SIZE] = "";
	char temp[PATH_SIZE];
	struct name_entry *name_loop;
	char *pos;
	int retval = 0;

	logging_init("udevinfo");

	udev_init_config();
	udev_init_device(&udev, NULL, NULL);

	/* get command line options */
	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'n':
			dbg("udev name: %s\n", optarg);
			strlcpy(name, optarg, sizeof(name));
			break;

		case 'p':
			dbg("udev path: %s\n", optarg);
			strlcpy(path, optarg, sizeof(path));
			break;

		case 'q':
			dbg("udev query: %s\n", optarg);

			if (strcmp(optarg, "name") == 0) {
				query = NAME;
				break;
			}

			if (strcmp(optarg, "symlink") == 0) {
				query = SYMLINK;
				break;
			}

			if (strcmp(optarg, "path") == 0) {
				query = PATH;
				break;
			}

			if (strcmp(optarg, "all") == 0) {
				query = ALL;
				break;
			}

			fprintf(stderr, "unknown query type\n");
			retval = 1;
			goto exit;

		case 'r':
			root = 1;
			break;

		case 'a':
			attributes = 1;
			break;

		case 'd':
			udev_db_dump_names(print_dump);
			goto exit;

		case 'V':
			printf("udevinfo, version %s\n", UDEV_VERSION);
			goto exit;

		case 'h':
			retval = 2;
		case '?':
		default:
			goto help;
		}
	}

	/* process options */
	if (query != NONE) {
		if (path[0] != '\0') {
			/* remove sysfs_path if given */
			if (strncmp(path, sysfs_path, strlen(sysfs_path)) == 0) {
				pos = path + strlen(sysfs_path);
			} else {
				if (path[0] != '/') {
					/* prepend '/' if missing */
					strcpy(temp, "/");
					strlcpy(temp, path, sizeof(temp));
					pos = temp;
				} else {
					pos = path;
				}
			}
			retval = udev_db_get_device(&udev, pos);
			if (retval != 0) {
				fprintf(stderr, "device not found in database\n");
				goto exit;
			}
			goto print;
		}

		if (name[0] != '\0') {
			char devpath[PATH_SIZE];
			int len;

			/* remove udev_root if given */
			len = strlen(udev_root);
			if (strncmp(name, udev_root, len) == 0) {
				pos = &name[len+1];
			} else
				pos = name;

			retval = udev_db_search_name(devpath, sizeof(devpath), pos);
			if (retval != 0) {
				fprintf(stderr, "device not found in database\n");
				goto exit;
			}
			udev_db_get_device(&udev, devpath);
			goto print;
		}

		fprintf(stderr, "query needs device path(-p) or node name(-n) specified\n");
		retval = 3;
		goto exit;

print:
		switch(query) {
		case NAME:
			if (root)
				printf("%s/%s\n", udev_root, udev.name);
			else
				printf("%s\n", udev.name);
			goto exit;
		case SYMLINK:
			if (list_empty(&udev.symlink_list))
				break;
			if (root)
				list_for_each_entry(name_loop, &udev.symlink_list, node)
					printf("%s/%s ", udev_root, name_loop->name);
			else
				list_for_each_entry(name_loop, &udev.symlink_list, node)
					printf("%s ", name_loop->name);
			printf("\n");
			goto exit;
		case PATH:
			printf("%s\n", udev.devpath);
			goto exit;
		case ALL:
			print_record(&udev);
			goto exit;
		default:
			goto help;
		}
	}

	if (attributes) {
		if (path[0] == '\0') {
			fprintf(stderr, "attribute walk on device chain needs path(-p) specified\n");
			retval = 4;
			goto exit;
		} else {
			if (strncmp(path, sysfs_path, strlen(sysfs_path)) != 0) {
				/* prepend sysfs mountpoint if not given */
				snprintf(temp, sizeof(temp), "%s%s", sysfs_path, path);
				temp[sizeof(temp)-1] = '\0';
				strlcpy(path, temp, sizeof(temp));
			}
			print_device_chain(path);
			goto exit;
		}
	}

	if (root) {
		printf("%s\n", udev_root);
		goto exit;
	}

help:
	fprintf(stderr, "Usage: udevinfo [-anpqrVh]\n"
	       "  -q TYPE  query database for the specified value:\n"
	       "             'name'    name of device node\n"
	       "             'symlink' pointing to node\n"
	       "             'path'    sysfs device path\n"
	       "             'all'     all values\n"
	       "\n"
	       "  -p PATH  sysfs device path used for query or chain\n"
	       "  -n NAME  node/symlink name used for query\n"
	       "\n"
	       "  -r       print udev root\n"
	       "  -a       print all SYSFS_attributes along the device chain\n"
	       "  -d       print the relationship of devpath and the node name for all\n"
	       "           devices available in the database\n"
	       "  -V       print udev version\n"
	       "  -h       print this help text\n"
	       "\n");

exit:
	udev_cleanup_device(&udev);
	logging_close();
	return retval;
}
