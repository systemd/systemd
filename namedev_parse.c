/*
 * namedev_parse.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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

#ifdef DEBUG
/* define this to enable parsing debugging also */
/* #define DEBUG_PARSER */
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "udev.h"
#include "udev_lib.h"
#include "logging.h"
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

void dump_config_dev(struct config_device *dev)
{
	dbg_parse("name='%s', symlink='%s', bus='%s', place='%s', id='%s', "
		  "sysfs_file[0]='%s', sysfs_value[0]='%s', "
		  "kernel='%s', program='%s', result='%s'"
		  "owner='%s', group='%s', mode=%#o",
		  dev->name, dev->symlink, dev->bus, dev->place, dev->id,
		  dev->sysfs_pair[0].file, dev->sysfs_pair[0].value,
		  dev->kernel, dev->program, dev->result,
		  dev->owner, dev->group, dev->mode);
}

void dump_config_dev_list(void)
{
	struct config_device *dev;

	list_for_each_entry(dev, &config_device_list, node)
		dump_config_dev(dev);
}

static int add_perm_dev(struct perm_device *new_dev)
{
	struct perm_device *dev;
	struct perm_device *tmp_dev;

	/* update the values if we already have the device */
	list_for_each_entry(dev, &perm_device_list, node) {
		if (strcmp(new_dev->name, dev->name) != 0)
			continue;

		set_empty_perms(dev, new_dev->mode, new_dev->owner, new_dev->group);
		return 0;
	}

	/* not found, add new structure to the perm list */
	tmp_dev = malloc(sizeof(*tmp_dev));
	if (!tmp_dev)
		return -ENOMEM;

	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add_tail(&tmp_dev->node, &perm_device_list);
	//dump_perm_dev(tmp_dev);
	return 0;
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

/* extract possible KEY{attr} or KEY_attr */
static char *get_key_attribute(char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			dbg("missing closing brace for format");
			return NULL;
		}
		pos[0] = '\0';
		dbg("attribute='%s'", attr);
		return attr;
	}

	attr = strchr(str, '_');
	if (attr != NULL) {
		attr++;
		dbg("attribute='%s'", attr);
		return attr;
	}

	return NULL;
}

static int namedev_parse_rules(const char *filename, void *data)
{
	char line[LINE_SIZE];
	char *bufline;
	int lineno;
	char *temp;
	char *temp2;
	char *temp3;
	char *attr;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int program_given = 0;
	int valid;
	int retval = 0;
	struct config_device dev;

	if (file_map(filename, &buf, &bufsize) == 0) {
		dbg("reading '%s' as rules file", filename);
	} else {
		dbg("can't open '%s' as rules file", filename);
		return -1;
	}

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= LINE_SIZE) {
			info("line too long, rule skipped %s, line %d",
			     filename, lineno);
			continue;
		}

		/* eat the whitespace */
		while ((count > 0) && isspace(bufline[0])) {
			bufline++;
			count--;
		}
		if (count == 0)
			continue;

		/* see if this is a comment */
		if (bufline[0] == COMMENT_CHARACTER)
			continue;

		strncpy(line, bufline, count);
		line[count] = '\0';
		dbg_parse("read '%s'", line);

		/* get all known keys */
		memset(&dev, 0x00, sizeof(struct config_device));
		temp = line;
		valid = 0;

		while (1) {
			retval = parse_get_pair(&temp, &temp2, &temp3);
			if (retval)
				break;

			if (strcasecmp(temp2, FIELD_BUS) == 0) {
				strfieldcpy(dev.bus, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_ID) == 0) {
				strfieldcpy(dev.id, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_PLACE) == 0) {
				strfieldcpy(dev.place, temp3);
				valid = 1;
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
					attr = get_key_attribute(temp2 + sizeof(FIELD_SYSFS)-1);
					if (attr == NULL) {
						dbg("error parsing " FIELD_SYSFS " attribute");
						continue;
					}
					strfieldcpy(pair->file, attr);
					strfieldcpy(pair->value, temp3);
					valid = 1;
				}
				continue;
			}

			if (strcasecmp(temp2, FIELD_KERNEL) == 0) {
				strfieldcpy(dev.kernel, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SUBSYSTEM) == 0) {
				strfieldcpy(dev.subsystem, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_DRIVER) == 0) {
				strfieldcpy(dev.driver, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_PROGRAM) == 0) {
				program_given = 1;
				strfieldcpy(dev.program, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_RESULT) == 0) {
				strfieldcpy(dev.result, temp3);
				valid = 1;
				continue;
			}

			if (strncasecmp(temp2, FIELD_NAME, sizeof(FIELD_NAME)-1) == 0) {
				attr = get_key_attribute(temp2 + sizeof(FIELD_NAME)-1);
				if (attr != NULL && strcasecmp(attr, ATTR_PARTITIONS) == 0) {
						dbg_parse("creation of partition nodes requested");
						dev.partitions = PARTITIONS_COUNT;
					}
				strfieldcpy(dev.name, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SYMLINK) == 0) {
				strfieldcpy(dev.symlink, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_OWNER) == 0) {
				strfieldcpy(dev.owner, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_GROUP) == 0) {
				strfieldcpy(dev.group, temp3);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_MODE) == 0) {
				dev.mode = strtol(temp3, NULL, 8);
				valid = 1;
				continue;
			}

			dbg("unknown type of field '%s'", temp2);
			goto error;
		}

		/* skip line if not any valid key was found */
		if (!valid)
			goto error;

		/* simple plausibility checks for given keys */
		if ((dev.sysfs_pair[0].file[0] == '\0') ^
		    (dev.sysfs_pair[0].value[0] == '\0')) {
			info("inconsistency in " FIELD_SYSFS " key");
			goto error;
		}

		if ((dev.result[0] != '\0') && (program_given == 0)) {
			info(FIELD_RESULT " is only useful when "
			     FIELD_PROGRAM " is called in any rule before");
			goto error;
		}

		dev.config_line = lineno;
		strfieldcpy(dev.config_file, filename);
		retval = add_config_dev(&dev);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			continue;
error:
			info("parse error %s, line %d:%d, rule skipped",
			     filename, lineno, temp - line);
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

static int namedev_parse_permissions(const char *filename, void *data)
{
	char line[LINE_SIZE];
	char *bufline;
	char *temp;
	char *temp2;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int retval = 0;
	struct perm_device dev;
	int lineno;

	if (file_map(filename, &buf, &bufsize) == 0) {
		dbg("reading '%s' as permissions file", filename);
	} else {
		dbg("can't open '%s' as permissions file", filename);
		return -1;
	}

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= LINE_SIZE) {
			info("line too long, rule skipped %s, line %d",
			     filename, lineno);
			continue;
		}

		/* eat the whitespace */
		while ((count > 0) && isspace(bufline[0])) {
			bufline++;
			count--;
		}
		if (count == 0)
			continue;

		/* see if this is a comment */
		if (bufline[0] == COMMENT_CHARACTER)
			continue;

		strncpy(line, bufline, count);
		line[count] = '\0';
		dbg_parse("read '%s'", line);

		/* parse the line */
		memset(&dev, 0x00, sizeof(struct perm_device));
		temp = line;

		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strfieldcpy(dev.name, temp2);

		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strfieldcpy(dev.owner, temp2);

		temp2 = strsep(&temp, ":");
		if (!temp2) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		strfieldcpy(dev.group, temp2);

		if (!temp) {
			dbg("cannot parse line '%s'", line);
			continue;
		}
		dev.mode = strtol(temp, NULL, 8);

		dbg_parse("name='%s', owner='%s', group='%s', mode=%#o",
			  dev.name, dev.owner, dev.group, dev.mode);

		retval = add_perm_dev(&dev);
		if (retval) {
			dbg("add_perm_dev returned with error %d", retval);
			goto exit;
		}
	}

exit:
	file_unmap(buf, bufsize);
	return retval;
}

int namedev_init_rules(void)
{
	struct stat stats;

	stat(udev_rules_filename, &stats);
	if ((stats.st_mode & S_IFMT) != S_IFDIR)
		return namedev_parse_rules(udev_rules_filename, NULL);
	else
		return call_foreach_file(namedev_parse_rules, udev_rules_filename,
					 RULEFILE_SUFFIX, NULL);
}

int namedev_init_permissions(void)
{
	struct stat stats;

	stat(udev_permissions_filename, &stats);
	if ((stats.st_mode & S_IFMT) != S_IFDIR)
		return namedev_parse_permissions(udev_permissions_filename, NULL);
	else
		return call_foreach_file(namedev_parse_permissions, udev_permissions_filename,
					 PERMFILE_SUFFIX, NULL);
}
