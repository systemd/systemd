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
#include <sysfs/libsysfs.h>

#include "udev.h"
#include "udev_version.h"
#include "logging.h"
#include "udevdb.h"


# define SYSFS_VALUE_MAX 200

char **main_argv;
int main_argc;

#ifdef LOG
unsigned char logname[42];
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
			strncpy(value, attr->value, SYSFS_VALUE_MAX);
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

/* callback for database dump */
static int print_record(char *path, struct udevice *dev)
{
	printf("P: %s\n", path);
	printf("N: %s\n", dev->name);
	printf("M: %#o\n", dev->mode);
	printf("S: %s\n", dev->symlink);
	printf("O: %s\n", dev->owner);
	printf("G: %s\n", dev->group);
	printf("\n");
	return 0;
}

enum query_type {
	NONE,
	NAME,
	PATH,
	SYMLINK,
	MODE,
	OWNER,
	GROUP
};

static int print_device_chain(const char *path)
{
	struct sysfs_class_device *class_dev;
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_attribute *attr;
	struct sysfs_device *sysfs_dev;
	struct sysfs_device *sysfs_dev_parent;
	int retval = 0;

	/*  get the class dev */
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		printf("couldn't get the class device\n");
		return -1;
	}

	/* read the 'dev' file for major/minor*/
	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr == NULL) {
		printf("couldn't get the \"dev\" file\n");
		retval = -1;
		goto exit;
	}
	printf("\ndevice '%s' has major:minor %s", class_dev->path, attr->value);
	sysfs_close_attribute(attr);

	/* open sysfs class device directory and print all attributes */
	printf("  looking at class device '%s':\n", class_dev->path);
	if (print_all_attributes(class_dev->path) != 0) {
		printf("couldn't open class device directory\n");
		retval = -1;
		goto exit;
	}

	/* get the device link (if parent exists look here) */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent != NULL) {
		//sysfs_close_class_device(class_dev);
		class_dev = class_dev_parent;
	}
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

		//sysfs_close_device(sysfs_dev);
		sysfs_dev = sysfs_dev_parent;
	}
	sysfs_close_device(sysfs_dev);

exit:
	//sysfs_close_class_device(class_dev);
	return retval;
}

static int process_options(void)
{
	static const char short_options[] = "adn:p:q:rVh";
	int option;
	int retval = 1;
	struct udevice dev;
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

			if (strcmp(optarg, "mode") == 0) {
				query = MODE;
				break;
			}

			if (strcmp(optarg, "owner") == 0) {
				query = OWNER;
				break;
			}

			if (strcmp(optarg, "group") == 0) {
				query = GROUP;
				break;
			}

			if (strcmp(optarg, "path") == 0) {
				query = PATH;
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

		case 'd':
			retval = udevdb_open_ro();
			if (retval != 0) {
				printf("unable to open udev database\n");
				exit(2);
			}
			udevdb_call_foreach(print_record);
			udevdb_exit();
			exit(0);

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
		retval = udevdb_open_ro();
		if (retval != 0) {
			printf("unable to open udev database\n");
			return -EACCES;
		}

		if (path[0] != '\0') {
			/* remove sysfs_path if given */
			if (strncmp(path, sysfs_path, strlen(sysfs_path)) == 0) {
				pos = path + strlen(sysfs_path);
			} else {
				if (path[0] != '/') {
					/* prepend '/' if missing */
					strcat(temp, "/");
					strncat(temp, path, sizeof(path));
					pos = temp;
				} else {
					pos = path;
				}
			}
			retval = udevdb_get_dev(pos, &dev);
			if (retval != 0) {
				printf("device not found in database\n");
				goto exit;
			}
			goto print;
		}

		if (name[0] != '\0') {
			/* remove udev_root if given */
			if (strncmp(name, udev_root, strlen(udev_root)) == 0) {
				pos = name + strlen(udev_root);
			} else
				pos = name;
			retval = udevdb_get_dev_byname(pos, path, &dev);
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
			if (root)
				strfieldcpy(result, udev_root);
			strncat(result, dev.name, sizeof(result));
			break;

		case SYMLINK:
			strfieldcpy(result, dev.symlink);
			break;

		case MODE:
			sprintf(result, "%#o", dev.mode);
			break;

		case GROUP:
			strfieldcpy(result, dev.group);
			break;

		case OWNER:
			strfieldcpy(result, dev.owner);
			break;

		case PATH:
			strfieldcpy(result, path);
			break;

		default:
			goto exit;
		}
		printf("%s\n", result);

exit:
		udevdb_exit();
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
				strncat(path, temp, sizeof(path));
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
	       "             'mode'    permissions of node\n"
	       "             'owner'   of node\n"
	       "             'group'   of node\n"
	       "             'path'    sysfs device path\n"
	       "  -p PATH  sysfs device path used for query or chain\n"
	       "  -n NAME  node name used for query\n"
	       "\n"
	       "  -r       print udev root\n"
	       "  -a       print all SYSFS_attributes along the device chain\n"
	       "  -d       dump whole database\n"
	       "  -V       print udev version\n"
	       "  -h       print this help text\n"
	       "\n");
	return retval;
}

int main(int argc, char *argv[], char *envp[])
{
	int retval;

	main_argv = argv;
	main_argc = argc;

	init_logging("udevinfo");

	/* initialize our configuration */
	udev_init_config();

	retval = process_options();
	if (retval != 0)
		exit(1);
	exit(0);
}
