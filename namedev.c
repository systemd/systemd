/*
 * namedev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
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

/* define this to enable parsing debugging */
#define DEBUG_PARSER 

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "list.h"
#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "libsysfs/libsysfs.h"

#define TYPE_LABEL	"LABEL"
#define TYPE_NUMBER	"NUMBER"
#define TYPE_TOPOLOGY	"TOPOLOGY"
#define TYPE_REPLACE	"REPLACE"
#define TYPE_CALLOUT	"CALLOUT"

static LIST_HEAD(config_device_list);

static void dump_dev(struct config_device *dev)
{
	switch (dev->type) {
	case KERNEL_NAME:
		dbg_parse("KERNEL name ='%s'"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, 
			dev->owner, dev->group, dev->mode);
		break;
	case LABEL:
		dbg_parse("LABEL name = '%s', bus = '%s', sysfs_file = '%s', sysfs_value = '%s'"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, dev->bus, dev->sysfs_file, dev->sysfs_value,
			dev->owner, dev->group, dev->mode);
		break;
	case NUMBER:
		dbg_parse("NUMBER name = '%s', bus = '%s', id = '%s'"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, dev->bus, dev->id,
			dev->owner, dev->group, dev->mode);
		break;
	case TOPOLOGY:
		dbg_parse("TOPOLOGY name = '%s', bus = '%s', place = '%s'"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, dev->bus, dev->place,
			dev->owner, dev->group, dev->mode);
		break;
	case REPLACE:
		dbg_parse("REPLACE name = %s, kernel_name = %s"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, dev->kernel_name,
			dev->owner, dev->group, dev->mode);
		break;
	case CALLOUT:
		dbg_parse("CALLOUT name = '%s', program ='%s', bus = '%s', id = '%s'"
			" owner = '%s', group = '%s', mode = '%#o'",
			dev->name, dev->exec_program, dev->bus, dev->id,
			dev->owner, dev->group, dev->mode);
		break;
	default:
		dbg_parse("Unknown type of device!");
	}
}

#define copy_var(a, b, var)		\
	if (b->var)			\
		a->var = b->var;

#define copy_string(a, b, var)		\
	if (strlen(b->var))		\
		strcpy(a->var, b->var);

static int add_dev(struct config_device *new_dev)
{
	struct list_head *tmp;
	struct config_device *tmp_dev;

	/* loop through the whole list of devices to see if we already have
	 * this one... */
	list_for_each(tmp, &config_device_list) {
		struct config_device *dev = list_entry(tmp, struct config_device, node);
		if (strcmp(dev->name, new_dev->name) == 0) {
			/* the same, copy the new info into this structure */
			copy_var(dev, new_dev, type);
			copy_var(dev, new_dev, mode);
			copy_string(dev, new_dev, bus);
			copy_string(dev, new_dev, sysfs_file);
			copy_string(dev, new_dev, sysfs_value);
			copy_string(dev, new_dev, id);
			copy_string(dev, new_dev, place);
			copy_string(dev, new_dev, kernel_name);
			copy_string(dev, new_dev, owner);
			copy_string(dev, new_dev, group);
			return 0;
		}
	}

	/* not found, lets create a new structure, and add it to the list */
	tmp_dev = malloc(sizeof(*tmp_dev));
	if (!tmp_dev)
		return -ENOMEM;
	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add(&tmp_dev->node, &config_device_list);
	//dump_dev(tmp_dev);
	return 0;
}

static void dump_dev_list(void)
{
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		struct config_device *dev = list_entry(tmp, struct config_device, node);
		dump_dev(dev);
	}
}

static int get_value(const char *left, char **orig_string, char **ret_string)
{
	char *temp;
	char *string = *orig_string;

	/* eat any whitespace */
	while (isspace(*string))
		++string;

	/* split based on '=' */
	temp = strsep(&string, "=");
	if (strcasecmp(temp, left) == 0) {
		/* got it, now strip off the '"' */
		while (isspace(*string))
			++string;
		if (*string == '"')
			++string;
		temp = strsep(&string, "\"");
		*ret_string = temp;
		*orig_string = string;
		return 0;
	}
	return -ENODEV;
}
	
static int get_pair(char **orig_string, char **left, char **right)
{
	char *temp;
	char *string = *orig_string;

	/* eat any whitespace */
	while (isspace(*string))
		++string;

	/* split based on '=' */
	temp = strsep(&string, "=");
	*left = temp;

	/* take the right side and strip off the '"' */
	while (isspace(*string))
		++string;
	if (*string == '"')
		++string;
	temp = strsep(&string, "\"");
	*right = temp;
	*orig_string = string;
	
	return 0;
}

static int namedev_init_config(void)
{
	char line[255];
	char *temp;
	char *temp2;
	char *temp3;
	FILE *fd;
	int retval = 0;
	struct config_device dev;

	dbg("opening %s to read as config", udev_config_filename);
	fd = fopen(udev_config_filename, "r");
	if (fd == NULL) {
		dbg("Can't open %s", udev_config_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	while (1) {
		/* get a line */
		temp = fgets(line, sizeof(line), fd);
		if (temp == NULL)
			break;

		dbg_parse("read %s", temp);

		/* eat the whitespace at the beginning of the line */
		while (isspace(*temp))
			++temp;

		/* no more line? */
		if (*temp == 0x00)
			continue;

		/* see if this is a comment */
		if (*temp == COMMENT_CHARACTER)
			continue;

		memset(&dev, 0x00, sizeof(struct config_device));

		/* parse the line */
		temp2 = strsep(&temp, ",");
		if (strcasecmp(temp2, TYPE_LABEL) == 0) {
			/* label type */
			dev.type = LABEL;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.bus, temp3);

			/* file="value" */
			temp2 = strsep(&temp, ",");
			retval = get_pair(&temp, &temp2, &temp3);
			if (retval)
				continue;
			strcpy(dev.sysfs_file, temp2);
			strcpy(dev.sysfs_value, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.name, temp3);

			dbg_parse("LABEL name = '%s', bus = '%s', "
				"sysfs_file = '%s', sysfs_value = '%s'", 
				dev.name, dev.bus, dev.sysfs_file, 
				dev.sysfs_value);
		}

		if (strcasecmp(temp2, TYPE_NUMBER) == 0) {
			/* number type */
			dev.type = NUMBER;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.bus, temp3);

			/* ID="id" */
			temp2 = strsep(&temp, ",");
			retval = get_value("id", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.id, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.name, temp3);

			dbg_parse("NUMBER name = '%s', bus = '%s', id = '%s'",
					dev.name, dev.bus, dev.id);
		}

		if (strcasecmp(temp2, TYPE_TOPOLOGY) == 0) {
			/* number type */
			dev.type = TOPOLOGY;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.bus, temp3);

			/* PLACE="place" */
			temp2 = strsep(&temp, ",");
			retval = get_value("place", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.place, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.name, temp3);

			dbg_parse("TOPOLOGY name = '%s', bus = '%s', place = '%s'",
					dev.name, dev.bus, dev.place);
		}

		if (strcasecmp(temp2, TYPE_REPLACE) == 0) {
			/* number type */
			dev.type = REPLACE;

			/* KERNEL="kernel_name" */
			retval = get_value("KERNEL", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.kernel_name, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.name, temp3);
			dbg_parse("REPLACE name = %s, kernel_name = %s",
					dev.name, dev.kernel_name);
		}
		if (strcasecmp(temp2, TYPE_CALLOUT) == 0) {
			/* number type */
			dev.type = CALLOUT;

			/* PROGRAM="executable" */
			retval = get_value("PROGRAM", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.exec_program, temp3);

			/* BUS="bus" */
			temp2 = strsep(&temp, ",");
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.bus, temp3);

			/* ID="id" */
			temp2 = strsep(&temp, ",");
			retval = get_value("ID", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.id, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				continue;
			strcpy(dev.name, temp3);
			dbg_parse("CALLOUT name = %s, program = %s",
					dev.name, dev.exec_program);
		}

		retval = add_dev(&dev);
		if (retval) {
			dbg("add_dev returned with error %d", retval);
			goto exit;
		}
	}

exit:
	fclose(fd);
	return retval;
}	


static int namedev_init_permissions(void)
{
	char line[255];
	char *temp;
	char *temp2;
	FILE *fd;
	int retval = 0;
	struct config_device dev;

	dbg("opening %s to read as permissions config", udev_config_permission_filename);
	fd = fopen(udev_config_permission_filename, "r");
	if (fd == NULL) {
		dbg("Can't open %s", udev_config_permission_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	while (1) {
		/* get a line */
		temp = fgets(line, sizeof(line), fd);
		if (temp == NULL)
			break;

		dbg_parse("read %s", temp);

		/* eat the whitespace at the beginning of the line */
		while (isspace(*temp))
			++temp;

		/* no more line? */
		if (*temp == 0x00)
			continue;

		/* see if this is a comment */
		if (*temp == COMMENT_CHARACTER)
			continue;

		memset(&dev, 0x00, sizeof(dev));

		/* parse the line */
		temp2 = strsep(&temp, ":");
		strncpy(dev.name, temp2, sizeof(dev.name));

		temp2 = strsep(&temp, ":");
		strncpy(dev.owner, temp2, sizeof(dev.owner));

		temp2 = strsep(&temp, ":");
		strncpy(dev.group, temp2, sizeof(dev.owner));

		dev.mode = strtol(temp, NULL, 8);

		dbg_parse("name = %s, owner = %s, group = %s, mode = %#o",
				dev.name, dev.owner, dev.group,
				dev.mode);
		retval = add_dev(&dev);
		if (retval) {
			dbg("add_dev returned with error %d", retval);
			goto exit;
		}
	}

exit:
	fclose(fd);
	return retval;
}	

static mode_t get_default_mode(struct sysfs_class_device *class_dev)
{
	/* just default everyone to rw for the world! */
	return 0666;
}


static int exec_callout(struct config_device *dev, char *value, int len)
{
	int retval;
	int res;
	int status;
	int fds[2];
	pid_t pid;
	int value_set = 0;
	char buffer[256];

	dbg("callout to %s\n", dev->exec_program);
	retval = pipe(fds);
	if (retval != 0) {
		dbg("pipe failed");
		return -1;
	}
	pid = fork();
	if (pid == -1) {
		dbg("fork failed");
		return -1;
	}

	if (pid == 0) {
		/*
		 * child 
		 */
		close(STDOUT_FILENO);
		dup(fds[1]);	/* dup write side of pipe to STDOUT */
		retval = execve(dev->exec_program, main_argv, main_envp);
		if (retval != 0) {
			dbg("child execve failed");
			exit(1);
		}
		return -1; /* avoid compiler warning */
	} else {
		/*
		 * Parent reads from fds[0].
		 */
		close(fds[1]);
		retval = 0;
		while (1) {
			res = read(fds[0], buffer, sizeof(buffer) - 1);
			if (res <= 0)
				break;
			buffer[res] = '\0';
			if (res > len) {
				dbg("callout len %d too short\n", len);
				retval = -1;
			}
			if (value_set) {
				dbg("callout value already set");
				retval = -1;
			} else {
				value_set = 1;
				strncpy(value, buffer, len);
			}
		}
		close(fds[0]);
		res = wait(&status);
		if (res < 0) {
			dbg("wait failed result %d", res);
			retval = -1;
		}

#ifndef __KLIBC__
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("callout program status 0x%x", status);
			retval = -1;
		}
#endif
	}
	return retval;
}

static int do_callout(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct config_device *dev;
	struct list_head *tmp;
	char value[ID_SIZE];

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != CALLOUT)
			continue;

		if (exec_callout(dev, value, sizeof(value)))
			continue;
		if (strncmp(value, dev->id, sizeof(value)) != 0)
			continue;
		strcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strcpy(udev->owner, dev->owner);
			strcpy(udev->group, dev->group);
		}
		dbg_parse("device callout '%s' becomes '%s' - owner = %s, group = %s, mode = %#o",
			dev->id, udev->name, 
			dev->owner, dev->group, dev->mode);
		return 0;
	}
	return -ENODEV;
}

static int do_replace(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct config_device *dev;
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != REPLACE)
			continue;

		dbg_parse("REPLACE: replace name '%s' with '%s'",
			  dev->kernel_name, dev->name);
		if (strcmp(dev->kernel_name, class_dev->name) != 0)
			continue;

		strcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strcpy(udev->owner, dev->owner);
			strcpy(udev->group, dev->group);
		}
		dbg_parse("'%s' becomes '%s' - owner = %s, group = %s, mode = %#o",
			dev->kernel_name, udev->name, 
			dev->owner, dev->group, dev->mode);
		
		return 0;
	}
	return -ENODEV;
}

static int get_attr(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct list_head *tmp;
	int retval = 0;
	int found;

	udev->mode = 0;
	if (class_dev->sysdevice) {
		dbg_parse("class_dev->sysdevice->path = '%s'", class_dev->sysdevice->path);
		dbg_parse("class_dev->sysdevice->bus_id = '%s'", class_dev->sysdevice->bus_id);
	} else {
		dbg_parse("class_dev->name = '%s'", class_dev->name);
	}
	list_for_each(tmp, &config_device_list) {
		struct config_device *dev = list_entry(tmp, struct config_device, node);
		switch (dev->type) {
		case LABEL:
			{
			struct sysfs_attribute *tmpattr = NULL;
			struct sysfs_class_device *class_dev_parent = NULL;
			char *temp = NULL;

			dbg_parse("LABEL: match file '%s' with value '%s'",
					dev->sysfs_file, dev->sysfs_value);
			/* try to find the attribute in the class device directory */
			tmpattr = sysfs_get_classdev_attr(class_dev, dev->sysfs_file);
			if (tmpattr)
				goto label_found;

			/* look in the class device directory if present */
			if (class_dev->sysdevice) {
				tmpattr = sysfs_get_device_attr(class_dev->sysdevice, dev->sysfs_file);
				if (tmpattr)
					goto label_found;
			}

			/* bah, let's go backwards up a level to see if the device is there,
			 * as block partitions don't point to the physical device.  Need to fix that
			 * up in the kernel...
			 */
			if (strstr(class_dev->path, "block")) {
				dbg_parse("looking at block device...");
				if (isdigit(class_dev->path[strlen(class_dev->path)-1])) {
					char path[SYSFS_PATH_MAX];

					dbg_parse("really is a partition...");
					strcpy(path, class_dev->path);
					temp = strrchr(path, '/');
					*temp = 0x00;
					dbg_parse("looking for a class device at '%s'", path);
					class_dev_parent = sysfs_open_class_device(path);
					if (class_dev_parent == NULL) {
						dbg("sysfs_open_class_device at '%s' failed", path);
						continue;
					}
					dbg_parse("class_dev_parent->name = %s", class_dev_parent->name);

					/* try to find the attribute in the class device directory */
					tmpattr = sysfs_get_classdev_attr(class_dev_parent, dev->sysfs_file);
					if (tmpattr) 
						goto label_found;

					/* look in the class device directory if present */
					if (class_dev_parent->sysdevice) {
						tmpattr = sysfs_get_device_attr(class_dev_parent->sysdevice, dev->sysfs_file);
						if (tmpattr) 
							goto label_found;
					}
					
				}
			}
			if (class_dev_parent)
				sysfs_close_class_device(class_dev_parent);

			continue;

label_found:
			tmpattr->value[strlen(tmpattr->value)-1] = 0x00;
			dbg_parse("file '%s' found with value '%s' compare with '%s'", dev->sysfs_file, tmpattr->value, dev->sysfs_value);
			if (strcmp(dev->sysfs_value, tmpattr->value) != 0) {
				if (class_dev_parent) 
					sysfs_close_class_device(class_dev_parent);
				continue;
			}

			strcpy(udev->name, dev->name);
			if (isdigit(class_dev->path[strlen(class_dev->path)-1])) {
				temp = &class_dev->path[strlen(class_dev->path)-1];
				strcat(udev->name, temp);
			}
			if (dev->mode != 0) {
				udev->mode = dev->mode;
				strcpy(udev->owner, dev->owner);
				strcpy(udev->group, dev->group);
			}
			dbg_parse("file '%s' with value '%s' becomes '%s' - owner = %s, group = %s, mode = %#o",
				dev->sysfs_file, dev->sysfs_value, udev->name, 
				dev->owner, dev->group, dev->mode);
			if (class_dev_parent)
				sysfs_close_class_device(class_dev_parent);
			goto done;
			break;
			}
		case NUMBER:
			{
			char path[SYSFS_PATH_MAX];
			char *temp;

			found = 0;
			if (!class_dev->sysdevice)
				continue;
			strcpy(path, class_dev->sysdevice->path);
			temp = strrchr(path, '/');
			dbg_parse("NUMBER path = '%s'", path);
			dbg_parse("NUMBER temp = '%s' id = '%s'", temp, dev->id);
			if (strstr(temp, dev->id) != NULL) {
				found = 1;
			} else {
				*temp = 0x00;
				temp = strrchr(path, '/');
				dbg_parse("NUMBERY temp = '%s' id = '%s'", temp, dev->id);
				if (strstr(temp, dev->id) != NULL)
					found = 1;
			}
			if (!found)
				continue;

			strcpy(udev->name, dev->name);
			if (dev->mode != 0) {
				udev->mode = dev->mode;
				strcpy(udev->owner, dev->owner);
				strcpy(udev->group, dev->group);
			}
			dbg_parse("device id '%s' becomes '%s' - owner = %s, group = %s, mode = %#o",
				dev->id, udev->name, 
				dev->owner, dev->group, dev->mode);
			goto done;
			break;
			}
		case TOPOLOGY:
			{
			char path[SYSFS_PATH_MAX];
			char *temp;

			if (!class_dev->sysdevice)
				continue;
			found = 0;	
			strcpy(path, class_dev->sysdevice->path);
			temp = strrchr(path, '/');
			dbg_parse("TOPOLOGY path = '%s'", path);
			dbg_parse("TOPOLOGY temp = '%s' place = '%s'", temp, dev->place);
			if (strstr(temp, dev->place) != NULL) {
				found = 1;
			} else {
				*temp = 0x00;
				temp = strrchr(path, '/');
				dbg_parse("TOPOLOGY temp = '%s' place = '%s'", temp, dev->place);
				if (strstr(temp, dev->place) != NULL)
					found = 1;
			}
			if (!found)
				continue;

			strcpy(udev->name, dev->name);
			if (dev->mode != 0) {
				udev->mode = dev->mode;
				strcpy(udev->owner, dev->owner);
				strcpy(udev->group, dev->group);
			}
			dbg_parse("device at '%s' becomes '%s' - owner = %s, group = %s, mode = %#o",
				dev->place, udev->name, 
				dev->owner, dev->group, dev->mode);
			goto done;
			break;
			}
		case KERNEL_NAME:
		default:
			break;
		}	
	}

	/* rules are looked at in priority order */

	retval = do_callout(class_dev, udev);
	if (retval == 0)
		goto done;

	retval = do_replace(class_dev, udev);
	if (retval == 0)
		goto done;

	strcpy(udev->name, class_dev->name);

done:
	/* mode was never set above */
	if (!udev->mode) {
		udev->mode = get_default_mode(class_dev);
		udev->owner[0] = 0x00;
		udev->group[0] = 0x00;
	}
	return 0;
}

int namedev_name_device(struct sysfs_class_device *class_dev, struct udevice *dev)
{
	int retval;

	retval = get_attr(class_dev, dev);
	if (retval)
		dbg("get_attr failed");

	return retval;
}

int namedev_init(void)
{
	int retval;
	
	retval = namedev_init_config();
	if (retval)
		return retval;

	retval = namedev_init_permissions();
	if (retval)
		return retval;

	dump_dev_list();
	return retval;
}


