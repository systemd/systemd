/*
 * namedev_parse.c
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
/* #define DEBUG_PARSER */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include "udev.h"
#include "namedev.h"

int get_pair(char **orig_string, char **left, char **right)
{
	char *temp;
	char *string = *orig_string;

	if (!string)
		return -ENODEV;

	/* eat any whitespace */
	while (isspace(*string))
		++string;

	/* split based on '=' */
	temp = strsep(&string, "=");
	*left = temp;
	if (!string)
		return -ENODEV;

	/* take the right side and strip off the '"' */
	while (isspace(*string))
		++string;
	if (*string == '"')
		++string;
	else
		return -ENODEV;

	temp = strsep(&string, "\"");
	if (!string || *temp == '\0')
		return -ENODEV;
	*right = temp;
	*orig_string = string;
	
	return 0;
}

static int get_value(const char *left, char **orig_string, char **ret_string)
{
	int retval;
	char *left_string;

	retval = get_pair(orig_string, &left_string, ret_string);
	if (retval)
		return retval;
	if (strcasecmp(left_string, left) != 0)
		return -ENODEV;
	return 0;
}

void dump_config_dev(struct config_device *dev)
{
	switch (dev->type) {
	case KERNEL_NAME:
		dbg_parse("KERNEL name='%s' ,"
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->owner, dev->group, dev->mode);
		break;
	case LABEL:
		dbg_parse("LABEL name='%s', bus='%s', sysfs_file='%s', sysfs_value='%s', "
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->bus, dev->sysfs_file, dev->sysfs_value,
			  dev->owner, dev->group, dev->mode);
		break;
	case NUMBER:
		dbg_parse("NUMBER name='%s', bus='%s', id='%s', "
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->bus, dev->id,
			  dev->owner, dev->group, dev->mode);
		break;
	case TOPOLOGY:
		dbg_parse("TOPOLOGY name='%s', bus='%s', place='%s', "
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->bus, dev->place,
			  dev->owner, dev->group, dev->mode);
		break;
	case REPLACE:
		dbg_parse("REPLACE name=%s, kernel_name=%s, "
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->kernel_name,
			  dev->owner, dev->group, dev->mode);
		break;
	case CALLOUT:
		dbg_parse("CALLOUT name='%s', bus='%s', program='%s', id='%s', "
			  "owner='%s', group='%s', mode=%#o",
			  dev->name, dev->bus, dev->exec_program, dev->id,
			  dev->owner, dev->group, dev->mode);
		break;
	default:
		dbg_parse("unknown type of method");
	}
}

void dump_config_dev_list(void)
{
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		struct config_device *dev = list_entry(tmp, struct config_device, node);
		dump_config_dev(dev);
	}
}
	
int namedev_init_rules(void)
{
	char line[255];
	int lineno;
	char *temp;
	char *temp2;
	char *temp3;
	FILE *fd;
	int retval = 0;
	struct config_device dev;

	fd = fopen(udev_rules_filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as rules file", udev_rules_filename);
	} else {
		dbg("can't open '%s' as a rules file", udev_rules_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	lineno = 0;
	while (1) {
		/* get a line */
		temp = fgets(line, sizeof(line), fd);
		if (temp == NULL)
			goto exit;
		lineno++;

		dbg_parse("read '%s'", temp);

		/* eat the whitespace at the beginning of the line */
		while (isspace(*temp))
			++temp;

		/* empty line? */
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
				break;
			strfieldcpy(dev.bus, temp3);

			/* file="value" */
			temp2 = strsep(&temp, ",");
			retval = get_pair(&temp, &temp2, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.sysfs_file, temp2);
			strfieldcpy(dev.sysfs_value, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.name, temp3);

			dbg_parse("LABEL name='%s', bus='%s', "
				  "sysfs_file='%s', sysfs_value='%s'",
				  dev.name, dev.bus, dev.sysfs_file,
				  dev.sysfs_value);
		}

		if (strcasecmp(temp2, TYPE_NUMBER) == 0) {
			/* number type */
			dev.type = NUMBER;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.bus, temp3);

			/* ID="id" */
			temp2 = strsep(&temp, ",");
			retval = get_value("ID", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.id, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.name, temp3);

			dbg_parse("NUMBER name='%s', bus='%s', id='%s'",
				  dev.name, dev.bus, dev.id);
		}

		if (strcasecmp(temp2, TYPE_TOPOLOGY) == 0) {
			/* number type */
			dev.type = TOPOLOGY;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.bus, temp3);

			/* PLACE="place" */
			temp2 = strsep(&temp, ",");
			retval = get_value("PLACE", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.place, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.name, temp3);

			dbg_parse("TOPOLOGY name='%s', bus='%s', place='%s'",
				  dev.name, dev.bus, dev.place);
		}

		if (strcasecmp(temp2, TYPE_REPLACE) == 0) {
			/* number type */
			dev.type = REPLACE;

			/* KERNEL="kernel_name" */
			retval = get_value("KERNEL", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.kernel_name, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.name, temp3);
			dbg_parse("REPLACE name='%s', kernel_name='%s'",
				  dev.name, dev.kernel_name);
		}
		if (strcasecmp(temp2, TYPE_CALLOUT) == 0) {
			/* number type */
			dev.type = CALLOUT;

			/* BUS="bus" */
			retval = get_value("BUS", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.bus, temp3);

			/* PROGRAM="executable" */
			temp2 = strsep(&temp, ",");
			retval = get_value("PROGRAM", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.exec_program, temp3);

			/* ID="id" */
			temp2 = strsep(&temp, ",");
			retval = get_value("ID", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.id, temp3);

			/* NAME="new_name" */
			temp2 = strsep(&temp, ",");
			retval = get_value("NAME", &temp, &temp3);
			if (retval)
				break;
			strfieldcpy(dev.name, temp3);
			dbg_parse("CALLOUT name='%s', program='%s'",
				  dev.name, dev.exec_program);
		}

		retval = add_config_dev(&dev);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			goto exit;
		}
	}
	dbg_parse("%s:%d:%Zd: error parsing '%s'", udev_rules_filename,
		  lineno, temp - line, temp);
exit:
	fclose(fd);
	return retval;
}	


int namedev_init_permissions(void)
{
	char line[255];
	char *temp;
	char *temp2;
	FILE *fd;
	int retval = 0;
	struct config_device dev;

	fd = fopen(udev_permission_filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as permissions file", udev_permission_filename);
	} else {
		dbg("can't open '%s' as permissions file", udev_permission_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	while (1) {
		temp = fgets(line, sizeof(line), fd);
		if (temp == NULL)
			break;

		dbg_parse("read '%s'", temp);

		/* eat the whitespace at the beginning of the line */
		while (isspace(*temp))
			++temp;

		/* empty line? */
		if (*temp == 0x00)
			continue;

		/* see if this is a comment */
		if (*temp == COMMENT_CHARACTER)
			continue;

		memset(&dev, 0x00, sizeof(dev));

		/* parse the line */
		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strncpy(dev.name, temp2, sizeof(dev.name));

		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strncpy(dev.owner, temp2, sizeof(dev.owner));

		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strncpy(dev.group, temp2, sizeof(dev.owner));

		if (!temp) {
			dbg("cannot parse line: %s", line);
			continue;
		}
		dev.mode = strtol(temp, NULL, 8);

		dbg_parse("name='%s', owner='%s', group='%s', mode=%#o",
			  dev.name, dev.owner, dev.group,
			  dev.mode);
		retval = add_config_dev(&dev);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			goto exit;
		}
	}

exit:
	fclose(fd);
	return retval;
}	


