/*
 * udevinfo - fetches attributes for a device
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
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
#include "libsysfs/dlist.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "udev_db.h"
#include "logging.h"


#define SYSFS_VALUE_SIZE		256

#ifdef LOG
void log_message (int level, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static void print_all_attributes(struct dlist *attr_list)
{
	struct sysfs_attribute *attr;
	char value[SYSFS_VALUE_SIZE];
	int len;

	dlist_for_each_data(attr_list, attr, struct sysfs_attribute) {
		if (attr->value != NULL) {
			strfieldcpy(value, attr->value);
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
				printf("    SYSFS{%s}=\"%s\"\n", attr->name, value);
		}
	}
	printf("\n");
}

static int print_record(struct udevice *udev)
{
	printf("P: %s\n", udev->devpath);
	printf("N: %s\n", udev->name);
	printf("S: %s\n", udev->symlink);
	printf("\n");
	return 0;
}

enum query_type {
	NONE,
	NAME,
	PATH,
	SYMLINK,
	ALL
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
		printf("couldn't get the class device\n");
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
	printf("    SUBSYSTEM=\"%s\"\n", class_dev->classname);

	attr_list = sysfs_get_classdev_attributes(class_dev);
	if (attr_list == NULL) {
		printf("couldn't open class device directory\n");
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
			printf("couldn't open device directory\n");
			retval = -1;
			goto exit;
		}

		printf("  looking at the device chain at '%s':\n", sysfs_dev->path);
		printf("    BUS=\"%s\"\n", sysfs_dev->bus);
		printf("    ID=\"%s\"\n", sysfs_dev->bus_id);
		printf("    DRIVER=\"%s\"\n", sysfs_dev->driver_name);

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

static int process_options(int argc, char *argv[])
{
	static const char short_options[] = "an:p:q:rVh";
	int option;
	int retval = 1;
	struct udevice udev;
	int root = 0;
	int attributes = 0;
	enum query_type query = NONE;
	char result[1024] = "";
	char path[NAME_SIZE] = "";
	char name[NAME_SIZE] = "";
	char temp[NAME_SIZE];
	char *pos;

	/* get command line options */
	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'n':
			dbg("udev name: %s\n", optarg);
			strfieldcpy(name, optarg);
			break;

		case 'p':
			dbg("udev path: %s\n", optarg);
			strfieldcpy(path, optarg);
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

			printf("unknown query type\n");
			exit(1);

		case 'r':
			root = 1;
			break;

		case 'a':
			attributes = 1;
			break;

		case 'V':
			printf("udevinfo, version %s\n", UDEV_VERSION);
			exit(0);

		case 'h':
			retval = 0;
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
					strfieldcat(temp, "/");
					strfieldcat(temp, path);
					pos = temp;
				} else {
					pos = path;
				}
			}
			memset(&udev, 0x00, sizeof(struct udevice));
			retval = udev_db_get_device_by_devpath(&udev, pos);
			if (retval != 0) {
				printf("device not found in database\n");
				goto exit;
			}
			goto print;
		}

		if (name[0] != '\0') {
			/* remove udev_root if given */
			int len = strlen(udev_root);

			if (strncmp(name, udev_root, len) == 0) {
				pos = &name[len+1];
			} else
				pos = name;

			memset(&udev, 0x00, sizeof(struct udevice));
			strfieldcpy(udev.name, pos);
			retval = udev_db_get_device_by_name(&udev, pos);
			if (retval != 0) {
				printf("device not found in database\n");
				goto exit;
			}

			goto print;
		}

		printf("query needs device path(-p) or node name(-n) specified\n");
		goto exit;

print:
		switch(query) {
		case NAME:
			if (root) {
				snprintf(result, NAME_SIZE-1, "%s/%s", udev_root, udev.name);
				result[NAME_SIZE-1] = '\0';
			} else {
				strfieldcpy(result, udev.name);
			}
			break;

		case SYMLINK:
			if (root) {
				int slen;
				char *spos;
				char slink[NAME_SIZE];

				pos = result;
				foreach_strpart(udev.symlink, " \n\r", spos, slen) {
					strncpy(slink, spos, slen);
					slink[slen] = '\0';
					pos += sprintf(pos, "%s/%s ", udev_root, slink);
				}
			} else {
				strfieldcpy(result, udev.symlink);
			}
			break;

		case PATH:
			strfieldcpy(result, udev.devpath);
			break;

		case ALL:
			print_record(&udev);
			goto exit;

		default:
			goto exit;
		}
		printf("%s\n", result);

exit:
		return retval;
	}

	if (attributes) {
		if (path[0] == '\0') {
			printf("attribute walk on device chain needs path(-p) specified\n");
			return -EINVAL;
		} else {
			if (strncmp(path, sysfs_path, strlen(sysfs_path)) != 0) {
				/* prepend sysfs mountpoint if not given */
				strfieldcpy(temp, path);
				strfieldcpy(path, sysfs_path);
				strfieldcat(path, temp);
			}
			print_device_chain(path);
			return 0;
		}
	}

	if (root) {
		printf("%s\n", udev_root);
		return 0;
	}

help:
	printf("Usage: udevinfo [-anpqrVh]\n"
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
	       "  -s       print all sysfs devices with major/minor, physical device and bus\n"
	       "  -V       print udev version\n"
	       "  -h       print this help text\n"
	       "\n");
	return retval;
}

int main(int argc, char *argv[], char *envp[])
{
	int rc = 0;

	logging_init("udevinfo");

	/* initialize our configuration */
	udev_init_config();

	rc = process_options(argc, argv);

	logging_close();
	exit(rc);
}
