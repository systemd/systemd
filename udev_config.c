/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>

#include "udev.h"

/* global variables */
char udev_root[PATH_SIZE];
char udev_config_filename[PATH_SIZE];
char udev_rules_dir[PATH_SIZE];
int udev_log_priority;
int udev_run;

static int get_key(char **line, char **key, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (!linepos)
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]))
		linepos++;

	/* get the key */
	*key = linepos;
	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
	}

	/* terminate key */
	linepos[0] = '\0';
	linepos++;

	/* skip whitespace */
	while (isspace(linepos[0]))
		linepos++;

	/* get the value*/
	if (linepos[0] == '"')
		linepos++;
	else
		return -1;
	*value = linepos;

	temp = strchr(linepos, '"');
	if (!temp)
		return -1;
	temp[0] = '\0';

	return 0;
}

static int parse_config_file(void)
{
	char line[LINE_SIZE];
	char *bufline;
	char *linepos;
	char *variable;
	char *value;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int lineno;
	int retval = 0;

	if (file_map(udev_config_filename, &buf, &bufsize) != 0) {
		err("can't open '%s' as config file: %s", udev_config_filename, strerror(errno));
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

		if (count >= sizeof(line)) {
			err("line too long, conf line skipped %s, line %d", udev_config_filename, lineno);
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

		memcpy(line, bufline, count);
		line[count] = '\0';

		linepos = line;
		retval = get_key(&linepos, &variable, &value);
		if (retval != 0) {
			err("error parsing %s, line %d:%d", udev_config_filename, lineno, (int)(linepos-line));
			continue;
		}

		if (strcasecmp(variable, "udev_root") == 0) {
			strlcpy(udev_root, value, sizeof(udev_root));
			remove_trailing_chars(udev_root, '/');
			continue;
		}

		if (strcasecmp(variable, "udev_rules") == 0) {
			strlcpy(udev_rules_dir, value, sizeof(udev_rules_dir));
			remove_trailing_chars(udev_rules_dir, '/');
			continue;
		}

		if (strcasecmp(variable, "udev_log") == 0) {
			udev_log_priority = log_priority(value);
			continue;
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

void udev_config_init(void)
{
	const char *env;

	strcpy(udev_root, UDEV_ROOT);
	strcpy(udev_config_filename, UDEV_CONFIG_FILE);
	strcpy(udev_rules_dir, UDEV_RULES_DIR);
	udev_log_priority = LOG_ERR;
	udev_run = 1;

	/* disable RUN key execution */
	env = getenv("UDEV_RUN");
	if (env && !string_is_true(env))
		udev_run = 0;

	env = getenv("UDEV_CONFIG_FILE");
	if (env) {
		strlcpy(udev_config_filename, env, sizeof(udev_config_filename));
		remove_trailing_chars(udev_config_filename, '/');
	}

	parse_config_file();

	env = getenv("UDEV_ROOT");
	if (env) {
		strlcpy(udev_root, env, sizeof(udev_root));
		remove_trailing_chars(udev_root, '/');
	}

	env = getenv("UDEV_LOG");
	if (env)
		udev_log_priority = log_priority(env);

	dbg("UDEV_CONFIG_FILE='%s'", udev_config_filename);
	dbg("udev_root='%s'", udev_root);
	dbg("udev_rules='%s'", udev_rules_dir);
	dbg("udev_log=%d", udev_log_priority);
}
