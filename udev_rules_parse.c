/*
 * udev_rules_parse.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2005 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "logging.h"
#include "udev_rules.h"

LIST_HEAD(udev_rule_list);

static int add_config_dev(struct udev_rule *rule)
{
	struct udev_rule *tmp_rule;

	tmp_rule = malloc(sizeof(*tmp_rule));
	if (tmp_rule == NULL)
		return -ENOMEM;
	memcpy(tmp_rule, rule, sizeof(struct udev_rule));
	list_add_tail(&tmp_rule->node, &udev_rule_list);

	dbg("name='%s', symlink='%s', bus='%s', id='%s', "
	    "sysfs_file[0]='%s', sysfs_value[0]='%s', "
	    "kernel='%s', program='%s', result='%s', "
	    "owner='%s', group='%s', mode=%#o, "
	    "all_partions=%u, ignore_remove=%u, ignore_device=%u, last_rule=%u",
	    rule->name, rule->symlink, rule->bus, rule->id,
	    rule->sysfs_pair[0].name, rule->sysfs_pair[0].value,
	    rule->kernel, rule->program, rule->result, rule->owner, rule->group, rule->mode,
	    rule->partitions, rule->ignore_remove, rule->ignore_device, rule->last_rule);

	return 0;
}

static int get_key(char **line, char **key, enum key_operation *operation, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (!linepos)
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
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
		if (linepos[0] == '+')
			break;
		if (linepos[0] == '!')
			break;
	}

	/* remember end of key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;

	/* get operation type */
	if (linepos[0] == '=' && linepos[1] == '=') {
		*operation = KEY_OP_MATCH;
		linepos += 2;
		dbg("operator=match");
	} else if (linepos[0] == '!' && linepos[1] == '=') {
		*operation = KEY_OP_NOMATCH;
		linepos += 2;
		dbg("operator=nomatch");
	} else if (linepos[0] == '+' && linepos[1] == '=') {
		*operation = KEY_OP_ADD;
		linepos += 2;
		dbg("operator=add");
	} else if (linepos[0] == '=') {
		*operation = KEY_OP_ASSIGN;
		linepos++;
		dbg("operator=assign");
	} else
		return -1;

	/* terminate key */
	temp[0] = '\0';
	dbg("key='%s'", *key);

	/* skip whitespace after operator */
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
	temp++;
	dbg("value='%s'", *value);

	/* move line to next key */
	*line = temp;

	return 0;
}

/* extract possible KEY{attr} */
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

	return NULL;
}

static int rules_parse(struct udevice *udev, const char *filename)
{
	char line[LINE_SIZE];
	char *bufline;
	int lineno;
	char *linepos;
	char *attr;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int program_given = 0;
	int valid;
	int retval = 0;
	struct udev_rule rule;

	if (file_map(filename, &buf, &bufsize) != 0) {
		dbg("can't open '%s' as rules file", filename);
		return -1;
	}
	dbg("reading '%s' as rules file", filename);

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		unsigned int i, j;

		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		if (count >= sizeof(line)) {
			info("line too long, rule skipped %s, line %d", filename, lineno);
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

		/* skip backslash and newline from multi line rules */
		for (i = j = 0; i < count; i++) {
			if (bufline[i] == '\\' && bufline[i+1] == '\n')
				continue;

			line[j++] = bufline[i];
		}
		line[j] = '\0';
		dbg("read '%s'", line);

		/* get all known keys */
		memset(&rule, 0x00, sizeof(struct udev_rule));
		linepos = line;
		valid = 0;

		while (1) {
			char *key;
			char *value;
			enum key_operation operation = KEY_OP_UNKNOWN;

			retval = get_key(&linepos, &key, &operation, &value);
			if (retval)
				break;

			if (strcasecmp(key, KEY_KERNEL) == 0) {
				strlcpy(rule.kernel, value, sizeof(rule.kernel));
				rule.kernel_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_SUBSYSTEM) == 0) {
				strlcpy(rule.subsystem, value, sizeof(rule.subsystem));
				rule.subsystem_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_BUS) == 0) {
				strlcpy(rule.bus, value, sizeof(rule.bus));
				rule.bus_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_ID) == 0) {
				strlcpy(rule.id, value, sizeof(rule.id));
				rule.id_operation = operation;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, KEY_SYSFS, sizeof(KEY_SYSFS)-1) == 0) {
				struct key_pair *pair;

				if (rule.sysfs_pair_count >= KEY_SYSFS_PAIRS_MAX) {
					dbg("skip rule, to many " KEY_SYSFS " keys in a single rule");
					goto error;
				}
				pair = &rule.sysfs_pair[rule.sysfs_pair_count];
				rule.sysfs_pair_count++;

				attr = get_key_attribute(key + sizeof(KEY_SYSFS)-1);
				if (attr == NULL) {
					dbg("error parsing " KEY_SYSFS " attribute");
					continue;
				}
				strlcpy(pair->name, attr, sizeof(pair->name));
				strlcpy(pair->value, value, sizeof(pair->value));
				pair->operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_DRIVER) == 0) {
				strlcpy(rule.driver, value, sizeof(rule.driver));
				rule.driver_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_RESULT) == 0) {
				strlcpy(rule.result, value, sizeof(rule.result));
				rule.result_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_PROGRAM) == 0) {
				strlcpy(rule.program, value, sizeof(rule.program));
				rule.program_operation = operation;
				program_given = 1;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, KEY_NAME, sizeof(KEY_NAME)-1) == 0) {
				attr = get_key_attribute(key + sizeof(KEY_NAME)-1);
				/* FIXME: remove old style options and make OPTIONS= mandatory */
				if (attr != NULL) {
					if (strstr(attr, OPTION_PARTITIONS) != NULL) {
						dbg("creation of partition nodes requested");
						rule.partitions = DEFAULT_PARTITIONS_COUNT;
					}
					if (strstr(attr, OPTION_IGNORE_REMOVE) != NULL) {
						dbg("remove event should be ignored");
						rule.ignore_remove = 1;
					}
				}
				if (value[0] != '\0')
					strlcpy(rule.name, value, sizeof(rule.name));
				else
					rule.ignore_device = 1;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_SYMLINK) == 0) {
				strlcpy(rule.symlink, value, sizeof(rule.symlink));
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_OWNER) == 0) {
				strlcpy(rule.owner, value, sizeof(rule.owner));
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_GROUP) == 0) {
				strlcpy(rule.group, value, sizeof(rule.group));
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_MODE) == 0) {
				rule.mode = strtol(value, NULL, 8);
				valid = 1;
				continue;
			}

			if (strcasecmp(key, KEY_OPTIONS) == 0) {
				if (strstr(value, OPTION_LAST_RULE) != NULL) {
					dbg("last rule to be applied");
					rule.last_rule = 1;
				}
				if (strstr(value, OPTION_IGNORE_DEVICE) != NULL) {
					dbg("device should be ignored");
					rule.ignore_device = 1;
				}
				if (strstr(value, OPTION_IGNORE_REMOVE) != NULL) {
					dbg("remove event should be ignored");
					rule.ignore_remove = 1;
				}
				if (strstr(value, OPTION_PARTITIONS) != NULL) {
					dbg("creation of partition nodes requested");
					rule.partitions = DEFAULT_PARTITIONS_COUNT;
				}
				valid = 1;
				continue;
			}

			dbg("unknown key '%s'", key);
			goto error;
		}

		/* skip line if not any valid key was found */
		if (!valid)
			goto error;

		/* simple plausibility checks for given keys */
		if ((rule.sysfs_pair[0].name[0] == '\0') ^
		    (rule.sysfs_pair[0].value[0] == '\0')) {
			info("inconsistency in " KEY_SYSFS " key");
			goto error;
		}

		if ((rule.result[0] != '\0') && (program_given == 0)) {
			info(KEY_RESULT " is only useful when "
			     KEY_PROGRAM " is called in any rule before");
			goto error;
		}

		rule.config_line = lineno;
		strlcpy(rule.config_file, filename, sizeof(rule.config_file));
		retval = add_config_dev(&rule);
		if (retval) {
			dbg("add_config_dev returned with error %d", retval);
			continue;
error:
			info("parse error %s, line %d:%d, rule skipped",
			     filename, lineno, (int) (linepos - line));
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

int udev_rules_init(void)
{
	struct stat stats;
	int retval;

	if (stat(udev_rules_filename, &stats) != 0)
		return -1;

	if ((stats.st_mode & S_IFMT) != S_IFDIR)
		retval = rules_parse(NULL, udev_rules_filename);
	else
		retval = call_foreach_file(rules_parse, NULL, udev_rules_filename, RULEFILE_SUFFIX);

	return retval;
}

void udev_rules_close(void)
{
	struct udev_rule *rule;
	struct udev_rule *temp_rule;

	list_for_each_entry_safe(rule, temp_rule, &udev_rule_list, node) {
		list_del(&rule->node);
		free(rule);
	}
}

