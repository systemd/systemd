/*
 * udev_config.c
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "udev.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "libsysfs/libsysfs.h"

/* global variables */
char sysfs_path[SYSFS_PATH_MAX];
char udev_root[PATH_MAX];
char udev_db_filename[PATH_MAX+NAME_MAX];
char udev_permissions_filename[PATH_MAX+NAME_MAX];
char udev_rules_filename[PATH_MAX+NAME_MAX];
char udev_config_filename[PATH_MAX+NAME_MAX];
char default_mode_str[NAME_MAX];


static void init_variables(void)
{
	/* fill up the defaults.  
	 * If any config values are specified, they will
	 * override these values. */
	strfieldcpy(udev_root, UDEV_ROOT);
	strfieldcpy(udev_db_filename, UDEV_DB);
	strfieldcpy(udev_config_filename, UDEV_CONFIG_FILE);
	strfieldcpy(udev_rules_filename, UDEV_RULES_FILE);
	strfieldcpy(udev_permissions_filename, UDEV_PERMISSION_FILE);
}

#define set_var(_name, _var)				\
	if (strcasecmp(variable, _name) == 0) {		\
		dbg_parse("%s = '%s'", _name, value);	\
		strncpy(_var, value, sizeof(_var));	\
	}

static int parse_config_file(void)
{
	char line[255];
	char *temp;
	char *variable;
	char *value;
	FILE *fd;
	int lineno = 0;
	int retval = 0;
	
	fd = fopen(udev_config_filename, "r");
	if (fd != NULL) {
		dbg("reading '%s' as config file", udev_config_filename);
	} else {
		dbg("can't open '%s' as config file", udev_config_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
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

		retval = get_pair(&temp, &variable, &value);
		if (retval)
			break;
		
		dbg_parse("variable = '%s', value = '%s'", variable, value);

		set_var("udev_root", udev_root);
		set_var("udev_db", udev_db_filename);
		set_var("udev_rules", udev_rules_filename);
		set_var("udev_permissions", udev_permissions_filename);
		set_var("default_mode", default_mode_str);
	}
	dbg_parse("%s:%d:%Zd: error parsing '%s'", udev_config_filename,
		  lineno, temp - line, temp);
exit:
	fclose(fd);
	return retval;
}

static void get_dirs(void)
{
	char *temp;
	int retval;

	retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
	if (retval)
		dbg("sysfs_get_mnt_path failed");

	/* see if we should try to override any of the default values */
	temp = getenv("UDEV_TEST");
	if (temp != NULL) {
		/* hm testing is happening, use the specified values, if they are present */
		temp = getenv("SYSFS_PATH");
		if (temp)
			strfieldcpy(sysfs_path, temp);
		temp = getenv("UDEV_CONFIG_FILE");
		if (temp)
			strfieldcpy(udev_config_filename, temp);
	}
	dbg("sysfs_path='%s'", sysfs_path);

	dbg_parse("udev_root = %s", udev_root);
	dbg_parse("udev_config_filename = %s", udev_config_filename);
	dbg_parse("udev_db_filename = %s", udev_db_filename);
	dbg_parse("udev_rules_filename = %s", udev_rules_filename);
	dbg_parse("udev_permissions_filename = %s", udev_permissions_filename);
	parse_config_file();

	dbg_parse("udev_root = %s", udev_root);
	dbg_parse("udev_config_filename = %s", udev_config_filename);
	dbg_parse("udev_db_filename = %s", udev_db_filename);
	dbg_parse("udev_rules_filename = %s", udev_rules_filename);
	dbg_parse("udev_permissions_filename = %s", udev_permissions_filename);
}

void udev_init_config(void)
{
	init_variables();
	get_dirs();
}


