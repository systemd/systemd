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

static int add_config_dev(struct config_device *new_dev)
{
	struct config_device *tmp_dev;

	tmp_dev = malloc(sizeof(*tmp_dev));
	if (tmp_dev == NULL)
		return -ENOMEM;
	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add_tail(&tmp_dev->node, &config_device_list);
	//dump_config_dev(tmp_dev);
	return 0;
}

int get_pair(char **orig_string, char **left, char **right)
{
	char *temp;
	char *string = *orig_string;

	if (!string)
		return -ENODEV;

	/* eat any whitespace */
	while (isspace(*string) || *string == ',')
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

void dump_config_dev(struct config_device *dev)
{
	switch (dev->type) {
	case KERNEL_NAME:
		dbg_parse("KERNEL name='%s'", dev->name);
		break;
	case LABEL:
		dbg_parse("LABEL name='%s', bus='%s', sysfs_file[0]='%s', sysfs_value[0]='%s'",
			  dev->name, dev->bus, dev->sysfs_pair[0].file, dev->sysfs_pair[0].value);
		break;
	case NUMBER:
		dbg_parse("NUMBER name='%s', bus='%s', id='%s'",
			  dev->name, dev->bus, dev->id);
		break;
	case TOPOLOGY:
		dbg_parse("TOPOLOGY name='%s', bus='%s', place='%s'",
			  dev->name, dev->bus, dev->place);
		break;
	case REPLACE:
		dbg_parse("REPLACE name='%s', kernel_name='%s'",
			  dev->name, dev->kernel_name);
		break;
	case CALLOUT:
		dbg_parse("CALLOUT name='%s', bus='%s', program='%s', id='%s'",
			  dev->name, dev->bus, dev->exec_program, dev->id);
		break;
	case IGNORE:
		dbg_parse("IGNORE name='%s', kernel_name='%s'",
			  dev->name, dev->kernel_name);
		break;
	default:
		dbg_parse("unknown type of method");
	}
}

void dump_config_dev_list(void)
{
	struct config_device *dev;

	list_for_each_entry(dev, &config_device_list, node)
		dump_config_dev(dev);
}

void dump_perm_dev(struct perm_device *dev)
{
	dbg_parse("name='%s', owner='%s', group='%s', mode=%#o",
		  dev->name, dev->owner, dev->group, dev->mode);
}

void dump_perm_dev_list(void)
{
	struct perm_device *dev;

	list_for_each_entry(dev, &perm_device_list, node)
		dump_perm_dev(dev);
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

		/* eat the whitespace */
		while (isspace(*temp))
			++temp;

		/* empty line? */
		if ((*temp == '\0') || (*temp == '\n'))
			continue;

		/* see if this is a comment */
		if (*temp == COMMENT_CHARACTER)
			continue;

		memset(&dev, 0x00, sizeof(struct config_device));

		/* get the method */
		temp2 = strsep(&temp, ",");

		if (strcasecmp(temp2, TYPE_LABEL) == 0) {
			dev.type = LABEL;
			goto keys;
		}

		if (strcasecmp(temp2, TYPE_NUMBER) == 0) {
			dev.type = NUMBER;
			goto keys;
		}

		if (strcasecmp(temp2, TYPE_TOPOLOGY) == 0) {
			dev.type = TOPOLOGY;
			goto keys;
		}

		if (strcasecmp(temp2, TYPE_REPLACE) == 0) {
			dev.type = REPLACE;
			goto keys;
		}

		if (strcasecmp(temp2, TYPE_CALLOUT) == 0) {
			dev.type = CALLOUT;
			goto keys;
		}

		if (strcasecmp(temp2, TYPE_IGNORE) == 0) {
			dev.type = IGNORE;
			goto keys;
		}

		dbg_parse("unknown type of method '%s'", temp2);
		goto error;
keys:
		/* get all known keys */
		while (1) {
			retval = get_pair(&temp, &temp2, &temp3);
			if (retval)
				break;

			if (strcasecmp(temp2, FIELD_BUS) == 0) {
				strfieldcpy(dev.bus, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_ID) == 0) {
				strfieldcpy(dev.id, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_PLACE) == 0) {
				strfieldcpy(dev.place, temp3);
				continue;
			}

			if (strncasecmp(temp2, FIELD_SYSFS, sizeof(FIELD_SYSFS)-1) == 0) {
				struct sysfs_pair *pair = &dev.sysfs_pair[0];
				int sysfs_pair_num = 0;

				/* find first unused pair */
				while (pair->file[0] != '\0') {
					++sysfs_pair_num;
					if (sysfs_pair_num >= MAX_SYSFS_PAIRS) {
						pair = NULL;
						break;
					}
					++pair;
				}
				if (pair) {
					/* remove prepended 'SYSFS_' */
					strfieldcpy(pair->file, temp2 + sizeof(FIELD_SYSFS)-1);
					strfieldcpy(pair->value, temp3);
				}
				continue;
			}

			if (strcasecmp(temp2, FIELD_KERNEL) == 0) {
				strfieldcpy(dev.kernel_name, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_PROGRAM) == 0) {
				strfieldcpy(dev.exec_program, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_NAME) == 0) {
				strfieldcpy(dev.name, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_SYMLINK) == 0) {
				strfieldcpy(dev.symlink, temp3);
				continue;
			}

			dbg_parse("unknown type of field '%s'", temp2);
		}

		/* check presence of keys according to method type */
		switch (dev.type) {
		case LABEL:
			dbg_parse(TYPE_LABEL " name='%s', bus='%s', "
				  "sysfs_file[0]='%s', sysfs_value[0]='%s', symlink='%s'",
				  dev.name, dev.bus, dev.sysfs_pair[0].file,
				  dev.sysfs_pair[0].value, dev.symlink);
			if ((*dev.name == '\0') ||
			    (*dev.sysfs_pair[0].file == '\0') ||
			    (*dev.sysfs_pair[0].value == '\0'))
				goto error;
			break;
		case NUMBER:
			dbg_parse(TYPE_NUMBER " name='%s', bus='%s', id='%s', symlink='%s'",
				  dev.name, dev.bus, dev.id, dev.symlink);
			if ((*dev.name == '\0') ||
			    (*dev.bus == '\0') ||
			    (*dev.id == '\0'))
				goto error;
			break;
		case TOPOLOGY:
			dbg_parse(TYPE_TOPOLOGY " name='%s', bus='%s', "
				  "place='%s', symlink='%s'",
				  dev.name, dev.bus, dev.place, dev.symlink);
			if ((*dev.name == '\0') ||
			    (*dev.bus == '\0') ||
			    (*dev.place == '\0'))
				goto error;
			break;
		case REPLACE:
			dbg_parse(TYPE_REPLACE " name='%s', kernel_name='%s', symlink='%s'",
				  dev.name, dev.kernel_name, dev.symlink);
			if ((*dev.name == '\0') ||
			    (*dev.kernel_name == '\0'))
				goto error;
			break;
		case CALLOUT:
			dbg_parse(TYPE_CALLOUT " name='%s', bus='%s', program='%s', "
				  "id='%s', symlink='%s'",
				  dev.name, dev.bus, dev.exec_program,
				  dev.id, dev.symlink);
			if ((*dev.name == '\0') ||
			    (*dev.id == '\0') ||
			    (*dev.exec_program == '\0'))
				goto error;
			break;
		case IGNORE:
			dbg_parse(TYPE_IGNORE "name='%s', kernel_name='%s'",
				  dev.name, dev.kernel_name);
			if ((*dev.kernel_name == '\0'))
				goto error;
			break;
		default:
			dbg_parse("unknown type of method");
			goto error;
		}

		retval = add_config_dev(&dev);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			continue;
		}
	}
error:
	dbg_parse("%s:%d:%Zd: field missing or parse error", udev_rules_filename,
		  lineno, temp - line);
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
	struct perm_device dev;

	fd = fopen(udev_permissions_filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as permissions file", udev_permissions_filename);
	} else {
		dbg("can't open '%s' as permissions file", udev_permissions_filename);
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
		if ((*temp == '\0') || (*temp == '\n'))
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
		retval = add_perm_dev(&dev);
		if (retval) {
			dbg("add_perm_dev returned with error %d", retval);
			goto exit;
		}
	}

exit:
	fclose(fd);
	return retval;
}	


