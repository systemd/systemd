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
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "udev.h"
#include "logging.h"
#include "namedev.h"

LIST_HEAD(file_list);


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
		  "kernel='%s', program='%s', result='%s'",
		  "owner='%s', group='%s', mode=%#o",
		  dev->name, dev->symlink, dev->bus, dev->place, dev->id,
		  dev->sysfs_pair[0].file, dev->sysfs_pair[0].value,
		  dev->kernel, dev->program, dev->result,;
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

static int namedev_parse_rules(char *filename)
{
	char line[255];
	int lineno;
	char *temp;
	char *temp2;
	char *temp3;
	char *attr;
	FILE *fd;
	int program_given = 0;
	int retval = 0;
	struct config_device dev;

	fd = fopen(filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as rules file", filename);
	} else {
		dbg("can't open '%s' as a rules file", filename);
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

		/* get all known keys */
		while (1) {
			retval = parse_get_pair(&temp, &temp2, &temp3);
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
					attr = get_key_attribute(temp2 + sizeof(FIELD_SYSFS)-1);
					if (attr == NULL) {
						dbg("error parsing " FIELD_SYSFS " attribute");
						continue;
					}
					strfieldcpy(pair->file, attr);
					strfieldcpy(pair->value, temp3);
				}
				continue;
			}

			if (strcasecmp(temp2, FIELD_KERNEL) == 0) {
				strfieldcpy(dev.kernel, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_PROGRAM) == 0) {
				program_given = 1;
				strfieldcpy(dev.program, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_RESULT) == 0) {
				strfieldcpy(dev.result, temp3);
				continue;
			}

			if (strncasecmp(temp2, FIELD_NAME, sizeof(FIELD_NAME)-1) == 0) {
				attr = get_key_attribute(temp2 + sizeof(FIELD_NAME)-1);
				if (attr != NULL)
					if (strcasecmp(attr, ATTR_PARTITIONS) == 0) {
						dbg_parse("creation of partition nodes requested");
						dev.partitions = PARTITIONS_COUNT;
					}
				strfieldcpy(dev.name, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_SYMLINK) == 0) {
				strfieldcpy(dev.symlink, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_OWNER) == 0) {
				strfieldcpy(dev.owner, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_GROUP) == 0) {
				strfieldcpy(dev.group, temp3);
				continue;
			}

			if (strcasecmp(temp2, FIELD_MODE) == 0) {
				dev.mode = strtol(temp3, NULL, 8);
				continue;
			}

			dbg("unknown type of field '%s'", temp2);
			goto error;
		}

		/* simple plausibility checks for given keys */
		if ((dev.sysfs_pair[0].file[0] == '\0') ^
		    (dev.sysfs_pair[0].value[0] == '\0')) {
			dbg("inconsistency in " FIELD_SYSFS " key");
			goto error;
		}

		if ((dev.result[0] != '\0') && (program_given == 0)) {
			dbg(FIELD_RESULT " is only useful when "
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
			dbg("%s:%d:%d: parse error, rule skipped",
			    filename, lineno, temp - line);
		}
	}
exit:
	fclose(fd);
	return retval;
}

static int namedev_parse_permissions(char *filename)
{
	char line[255];
	char *temp;
	char *temp2;
	FILE *fd;
	int retval = 0;
	struct perm_device dev;

	fd = fopen(filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as permissions file", filename);
	} else {
		dbg("can't open '%s' as permissions file", filename);
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
	fclose(fd);
	return retval;
}

struct files {
	struct list_head list;
	char name[NAME_SIZE];
};

/* sort files in lexical order */
static int file_list_insert(char *filename)
{
	struct files *loop_file;
	struct files *new_file;

	list_for_each_entry(loop_file, &file_list, list) {
		if (strcmp(loop_file->name, filename) > 0) {
			break;
		}
	}

	new_file = malloc(sizeof(struct files));
	if (new_file == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strfieldcpy(new_file->name, filename);
	list_add_tail(&new_file->list, &loop_file->list);
	return 0;
}

/* calls function for file or every file found in directory */
static int call_foreach_file(int parser (char *f) , char *filename, char *extension)
{
	struct dirent *ent;
	DIR *dir;
	char *ext;
	char file[NAME_SIZE];
	struct stat stats;
	struct files *loop_file;
	struct files *tmp_file;

	/* look if we have a plain file or a directory to scan */
	stat(filename, &stats);
	if ((stats.st_mode & S_IFMT) != S_IFDIR)
		return parser(filename);

	/* sort matching filename into list */
	dbg("open config as directory '%s'", filename);
	dir = opendir(filename);
	while (1) {
		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;

		dbg("found file '%s'", ent->d_name);
		ext = strrchr(ent->d_name, '.');
		if (ext == NULL)
			continue;

		if (strcmp(ext, extension) == 0) {
			dbg("put file in list '%s'", ent->d_name);
			file_list_insert(ent->d_name);
		}
	}

	/* parse every file in the list */
	list_for_each_entry_safe(loop_file, tmp_file, &file_list, list) {
		strfieldcpy(file, filename);
		strfieldcat(file, loop_file->name);
		parser(file);
		list_del(&loop_file->list);
		free(loop_file);
	}

	closedir(dir);
	return 0;
}

int namedev_init_rules()
{
	return call_foreach_file(namedev_parse_rules, udev_rules_filename, RULEFILE_EXT);
}

int namedev_init_permissions()
{
	return call_foreach_file(namedev_parse_permissions, udev_permissions_filename, PERMFILE_EXT);
}
