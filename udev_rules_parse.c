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

static int add_config_dev(struct udev_rule *new_rule)
{
	struct udev_rule *tmp_rule;

	tmp_rule = malloc(sizeof(*tmp_rule));
	if (tmp_rule == NULL)
		return -ENOMEM;
	memcpy(tmp_rule, new_rule, sizeof(*tmp_rule));
	list_add_tail(&tmp_rule->node, &udev_rule_list);
	udev_rule_dump(tmp_rule);

	return 0;
}

void udev_rule_dump(struct udev_rule *rule)
{
	dbg("name='%s', symlink='%s', bus='%s', id='%s', "
	    "sysfs_file[0]='%s', sysfs_value[0]='%s', "
	    "kernel='%s', program='%s', result='%s'"
	    "owner='%s', group='%s', mode=%#o",
	    rule->name, rule->symlink, rule->bus, rule->id,
	    rule->sysfs_pair[0].file, rule->sysfs_pair[0].value,
	    rule->kernel, rule->program, rule->result,
	    rule->owner, rule->group, rule->mode);
}

void udev_rule_list_dump(void)
{
	struct udev_rule *rule;

	list_for_each_entry(rule, &udev_rule_list, node)
		udev_rule_dump(rule);
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
	struct udev_rule rule;

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
		temp = line;
		valid = 0;

		while (1) {
			retval = parse_get_pair(&temp, &temp2, &temp3);
			if (retval)
				break;

			if (strcasecmp(temp2, FIELD_KERNEL) == 0) {
				strlcpy(rule.kernel, temp3, sizeof(rule.kernel));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SUBSYSTEM) == 0) {
				strlcpy(rule.subsystem, temp3, sizeof(rule.subsystem));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_BUS) == 0) {
				strlcpy(rule.bus, temp3, sizeof(rule.bus));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_ID) == 0) {
				strlcpy(rule.id, temp3, sizeof(rule.id));
				valid = 1;
				continue;
			}

			if (strncasecmp(temp2, FIELD_SYSFS, sizeof(FIELD_SYSFS)-1) == 0) {
				struct sysfs_pair *pair = &rule.sysfs_pair[0];
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
					strlcpy(pair->file, attr, sizeof(pair->file));
					strlcpy(pair->value, temp3, sizeof(pair->value));
					valid = 1;
				}
				continue;
			}

			if (strcasecmp(temp2, FIELD_DRIVER) == 0) {
				strlcpy(rule.driver, temp3, sizeof(rule.driver));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_PROGRAM) == 0) {
				program_given = 1;
				strlcpy(rule.program, temp3, sizeof(rule.program));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_RESULT) == 0) {
				strlcpy(rule.result, temp3, sizeof(rule.result));
				valid = 1;
				continue;
			}

			if (strncasecmp(temp2, FIELD_NAME, sizeof(FIELD_NAME)-1) == 0) {
				attr = get_key_attribute(temp2 + sizeof(FIELD_NAME)-1);
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
				if (temp3[0] != '\0')
					strlcpy(rule.name, temp3, sizeof(rule.name));
				else
					rule.ignore_device = 1;
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_SYMLINK) == 0) {
				strlcpy(rule.symlink, temp3, sizeof(rule.symlink));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_OWNER) == 0) {
				strlcpy(rule.owner, temp3, sizeof(rule.owner));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_GROUP) == 0) {
				strlcpy(rule.group, temp3, sizeof(rule.group));
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_MODE) == 0) {
				rule.mode = strtol(temp3, NULL, 8);
				valid = 1;
				continue;
			}

			if (strcasecmp(temp2, FIELD_OPTIONS) == 0) {
				if (strstr(temp3, OPTION_IGNORE_DEVICE) != NULL) {
					dbg("device should be ignored");
					rule.ignore_device = 1;
				}
				if (strstr(temp3, OPTION_IGNORE_REMOVE) != NULL) {
					dbg("remove event should be ignored");
					rule.ignore_remove = 1;
				}
				if (strstr(temp3, OPTION_PARTITIONS) != NULL) {
					dbg("creation of partition nodes requested");
					rule.partitions = DEFAULT_PARTITIONS_COUNT;
				}
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
		if ((rule.sysfs_pair[0].file[0] == '\0') ^
		    (rule.sysfs_pair[0].value[0] == '\0')) {
			info("inconsistency in " FIELD_SYSFS " key");
			goto error;
		}

		if ((rule.result[0] != '\0') && (program_given == 0)) {
			info(FIELD_RESULT " is only useful when "
			     FIELD_PROGRAM " is called in any rule before");
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
			     filename, lineno, (int) (temp - line));
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

