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
#include "udev_lib.h"
#include "udev_version.h"
#include "logging.h"
#include "udevdb.h"


# define SYSFS_VALUE_MAX 200

char **main_argv;
int main_argc;

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message (int level, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static int print_all_attributes(const char *path)
{
	struct dlist *attributes;
	struct sysfs_attribute *attr;
	struct sysfs_directory *sysfs_dir;
	char value[SYSFS_VALUE_MAX];
	int len;
	int retval = 0;

	sysfs_dir = sysfs_open_directory(path);
	if (sysfs_dir == NULL)
		return -1;

	attributes = sysfs_get_dir_attributes(sysfs_dir);
	if (attributes == NULL) {
		retval = -1;
		goto exit;
	}

	dlist_for_each_data(attributes, attr, struct sysfs_attribute) {
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

exit:
	sysfs_close_directory(sysfs_dir);

	return retval;
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
	int retval = 0;
	char type;

	type = get_device_type(path, "");
	dbg("device type is %c", type);

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

	if (type == 'b' || type =='c') {
		/* read the 'dev' file for major/minor*/
		attr = sysfs_get_classdev_attr(class_dev, "dev");
		if (attr == NULL) {
			printf("couldn't get the \"dev\" file\n");
			retval = -1;
			goto exit;
		}
		printf("device '%s' has major:minor %s", class_dev->path, attr->value);
	}

	/* open sysfs class device directory and print all attributes */
	printf("  looking at class device '%s':\n", class_dev->path);
	if (print_all_attributes(class_dev->path) != 0) {
		printf("couldn't open class device directory\n");
		retval = -1;
		goto exit;
	}

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
		printf("  looking at the device chain at '%s':\n", sysfs_dev->path);
		printf("    BUS=\"%s\"\n", sysfs_dev->bus);
		printf("    ID=\"%s\"\n", sysfs_dev->bus_id);

		/* open sysfs device directory and print all attributes */
		print_all_attributes(sysfs_dev->path);

		sysfs_dev_parent = sysfs_get_device_parent(sysfs_dev);
		if (sysfs_dev_parent == NULL)
			break;

		sysfs_dev = sysfs_dev_parent;
	}

exit:
	sysfs_close_class_device(class_dev);
	return retval;
}

/* print all class/block devices with major/minor, physical device and bus*/
static void print_sysfs_devices(void)
{
	struct dlist *subsyslist;
	char *class;

	subsyslist = sysfs_open_subsystem_list("class");
	if (!subsyslist)
		exit(1);

	dlist_for_each_data(subsyslist, class, char) {
		struct sysfs_class *cls;
		struct dlist *class_devices;
		struct sysfs_class_device *class_dev;
		struct sysfs_device *phys_dev;

		cls = sysfs_open_class(class);
		if (!cls)
			continue;

		class_devices = sysfs_get_class_devices(cls);
		if (!class_devices)
			continue;

		dlist_for_each_data(class_devices, class_dev, struct sysfs_class_device) {
			struct sysfs_attribute *attr;

			printf("\n");
			printf("DEVPATH        '%s'\n", class_dev->path);
			printf("SUBSYSTEM      '%s'\n", class_dev->classname);
			printf("NAME           '%s'\n", class_dev->name);

			attr = sysfs_get_classdev_attr(class_dev, "dev");
			if (attr) {
				char *pos = &(attr->value[strlen(attr->value)-1]);

				if  (pos[0] == '\n')
					pos[0] = '\0';

				printf("MAJORMINOR     '%s'\n", attr->value);
			}

			phys_dev = sysfs_get_classdev_device(class_dev);
			if (phys_dev) {
				printf("PHYSDEVPATH    '%s'\n", phys_dev->path);
				if (phys_dev->bus[0] != '\0')
					printf("PHYSDEVPATHBUS '%s'\n", phys_dev->bus);
				if (phys_dev->driver_name[0] != '\0')
					printf("DRIVER         '%s'\n", phys_dev->driver_name);
			}
		}

		sysfs_close_class(cls);
	}

	sysfs_close_list(subsyslist);
}

static int process_options(void)
{
	static const char short_options[] = "adn:p:q:rsVh";
	int option;
	int retval = 1;
	struct udevice udev;
	int root = 0;
	int attributes = 0;
	enum query_type query = NONE;
	char result[NAME_SIZE] = "";
	char path[NAME_SIZE] = "";
	char name[NAME_SIZE] = "";
	char temp[NAME_SIZE];
	char *pos;

	/* get command line options */
	while (1) {
		option = getopt(main_argc, main_argv, short_options);
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

		case 's':
			print_sysfs_devices();
			exit(0);

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
			strfieldcpy(udev.devpath, pos);
			retval = udevdb_get_dev(&udev);
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
			retval = udevdb_get_dev_byname(&udev, pos);
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
			strfieldcpy(result, udev.symlink);
			break;

		case PATH:
			strfieldcpy(result, path);
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
	printf("Usage: [-anpqrdVh]\n"
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

	main_argv = argv;
	main_argc = argc;

	logging_init("udevinfo");

	/* initialize our configuration */
	udev_init_config();

	rc = process_options();

	logging_close();
	exit(rc);
}
