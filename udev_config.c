/*
 * udev_config.c
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

/* define this to enable parsing debugging */
/* #define DEBUG_PARSER */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"

/* global variables */
char sysfs_path[SYSFS_PATH_MAX];
char udev_root[PATH_MAX];
char udev_db_path[PATH_MAX+NAME_MAX];
char udev_rules_filename[PATH_MAX+NAME_MAX];
char udev_config_filename[PATH_MAX+NAME_MAX];
int udev_log;
int udev_dev_d;
int udev_hotplug_d;


static int string_is_true(const char *str)
{
	if (strcasecmp(str, "true") == 0)
		return 1;
	if (strcasecmp(str, "yes") == 0)
		return 1;
	if (strcasecmp(str, "1") == 0)
		return 1;
	return 0;
}

static void init_variables(void)
{
	const char *env;

	/* If any config values are specified, they will override these values. */
	strcpy(udev_root, UDEV_ROOT);
	strcpy(udev_db_path, UDEV_DB);
	strcpy(udev_config_filename, UDEV_CONFIG_FILE);
	strcpy(udev_rules_filename, UDEV_RULES_FILE);

	udev_log = string_is_true(UDEV_LOG_DEFAULT);

	udev_dev_d = 1;
	env = getenv("UDEV_NO_DEVD");
	if (env && string_is_true(env))
		udev_dev_d = 0;

	udev_hotplug_d = 1;
	env = getenv("UDEV_NO_HOTPLUGD");
	if (env && string_is_true(env))
		udev_hotplug_d = 0;
}

static int parse_config_file(void)
{
	char line[LINE_SIZE];
	char *bufline;
	char *temp;
	char *variable;
	char *value;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int lineno;
	int retval = 0;

	if (file_map(udev_config_filename, &buf, &bufsize) == 0) {
		dbg("reading '%s' as config file", udev_config_filename);
	} else {
		dbg("can't open '%s' as config file", udev_config_filename);
		return -ENODEV;
	}

	/* loop through the whole file */
	lineno = 0;
	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= LINE_SIZE) {
			info("line too long, conf line skipped %s, line %d",
					udev_config_filename, lineno);
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
		temp = line;
		dbg_parse("read '%s'", temp);

		retval = parse_get_pair(&temp, &variable, &value);
		if (retval != 0)
			info("%s:%d:%Zd: error parsing '%s'",
			     udev_config_filename, lineno, temp-line, temp);

		dbg_parse("variable='%s', value='%s'", variable, value);

		if (strcasecmp(variable, "udev_root") == 0) {
			strfieldcpy(udev_root, value);
			no_trailing_slash(udev_root);
			continue;
		}

		if (strcasecmp(variable, "udev_db") == 0) {
			strfieldcpy(udev_db_path, value);
			no_trailing_slash(udev_db_path);
			continue;
		}

		if (strcasecmp(variable, "udev_rules") == 0) {
			strfieldcpy(udev_rules_filename, value);
			no_trailing_slash(udev_rules_filename);
			continue;
		}

		if (strcasecmp(variable, "udev_log") == 0) {
			udev_log = string_is_true(value);
			continue;
		}

		info("%s:%d:%Zd: unknown key '%s'",
		     udev_config_filename, lineno, temp-line, temp);
	}

	file_unmap(buf, bufsize);
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
	if (getenv("UDEV_TEST") != NULL) {
		temp = getenv("SYSFS_PATH");
		if (temp != NULL) {
			strfieldcpy(sysfs_path, temp);
			no_trailing_slash(sysfs_path);
		}

		temp = getenv("UDEV_CONFIG_FILE");
		if (temp != NULL)
			strfieldcpy(udev_config_filename, temp);
	}

	parse_config_file();
	dbg("sysfs_path='%s'", sysfs_path);
	dbg("udev_root='%s'", udev_root);
	dbg("udev_config_filename='%s'", udev_config_filename);
	dbg("udev_db_path='%s'", udev_db_path);
	dbg("udev_rules_filename='%s'", udev_rules_filename);
	dbg("udev_log=%d", udev_log);
}

void udev_init_config(void)
{
	init_variables();
	get_dirs();
}
