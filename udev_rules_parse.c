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

/* rules parsed from .rules files*/
static LIST_HEAD(rules_list);
static struct list_head *rules_list_current;

/* mapped compiled rules stored on disk */
static struct udev_rule *rules_array = NULL;
static size_t rules_array_current;
static size_t rules_array_size = 0;

static size_t rules_count = 0;

int udev_rules_iter_init(void)
{
	rules_list_current = rules_list.next;
	rules_array_current = 0;

	return 0;
}

struct udev_rule *udev_rules_iter_next(void)
{
	static struct udev_rule *rule;

	if (rules_array) {
		if (rules_array_current >= rules_count)
			return NULL;
		rule = &rules_array[rules_array_current];
		rules_array_current++;
	} else {
		dbg("head=%p current=%p next=%p", &rules_list, rules_list_current, rules_list_current->next);
		if (rules_list_current == &rules_list)
			return NULL;
		rule = list_entry(rules_list_current, struct udev_rule, node);
		rules_list_current = rules_list_current->next;
	}
	return rule;
}

static int add_rule_to_list(struct udev_rule *rule)
{
	struct udev_rule *tmp_rule;

	tmp_rule = malloc(sizeof(*tmp_rule));
	if (tmp_rule == NULL)
		return -ENOMEM;
	memcpy(tmp_rule, rule, sizeof(struct udev_rule));
	list_add_tail(&tmp_rule->node, &rules_list);

	dbg("name='%s', symlink='%s', bus='%s', id='%s', "
	    "sysfs_file[0]='%s', sysfs_value[0]='%s', "
	    "kernel_name='%s', program='%s', result='%s', "
	    "owner='%s', group='%s', mode=%#o, "
	    "all_partions=%u, ignore_remove=%u, ignore_device=%u, last_rule=%u",
	    rule->name, rule->symlink, rule->bus, rule->id,
	    rule->sysfs_pair[0].name, rule->sysfs_pair[0].value,
	    rule->kernel_name, rule->program, rule->result, rule->owner, rule->group, rule->mode,
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
		if (linepos[0] == ':')
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
	} else if (linepos[0] == ':' && linepos[1] == '=') {
		*operation = KEY_OP_ASSIGN_FINAL;
		linepos += 2;
		dbg("operator=assign_final");
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
			err("missing closing brace for format");
			return NULL;
		}
		pos[0] = '\0';
		dbg("attribute='%s'", attr);
		return attr;
	}

	return NULL;
}

static int rules_parse(const char *filename)
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
		err("can't open '%s' as rules file", filename);
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
			enum key_operation operation = KEY_OP_UNSET;

			retval = get_key(&linepos, &key, &operation, &value);
			if (retval)
				break;

			if (strcasecmp(key, "KERNEL") == 0) {
				strlcpy(rule.kernel_name, value, sizeof(rule.kernel_name));
				rule.kernel_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "SUBSYSTEM") == 0) {
				strlcpy(rule.subsystem, value, sizeof(rule.subsystem));
				rule.subsystem_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "ACTION") == 0) {
				strlcpy(rule.action, value, sizeof(rule.action));
				rule.action_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "DEVPATH") == 0) {
				strlcpy(rule.devpath, value, sizeof(rule.devpath));
				rule.devpath_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "BUS") == 0) {
				strlcpy(rule.bus, value, sizeof(rule.bus));
				rule.bus_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "ID") == 0) {
				strlcpy(rule.id, value, sizeof(rule.id));
				rule.id_operation = operation;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, "SYSFS", sizeof("SYSFS")-1) == 0) {
				struct key_pair *pair;

				if (rule.sysfs_pair_count >= KEY_SYSFS_PAIRS_MAX) {
					err("skip rule, to many SYSFS keys in a single rule");
					goto error;
				}
				pair = &rule.sysfs_pair[rule.sysfs_pair_count];
				attr = get_key_attribute(key + sizeof("SYSFS")-1);
				if (attr == NULL) {
					err("error parsing SYSFS attribute");
					goto error;
				}
				strlcpy(pair->name, attr, sizeof(pair->name));
				strlcpy(pair->value, value, sizeof(pair->value));
				pair->operation = operation;
				rule.sysfs_pair_count++;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, "ENV", sizeof("ENV")-1) == 0) {
				struct key_pair *pair;

				if (rule.env_pair_count >= KEY_ENV_PAIRS_MAX) {
					err("skip rule, to many ENV keys in a single rule");
					goto error;
				}
				pair = &rule.env_pair[rule.env_pair_count];
				attr = get_key_attribute(key + sizeof("ENV")-1);
				if (attr == NULL) {
					err("error parsing ENV attribute");
					continue;
				}
				strlcpy(pair->name, attr, sizeof(pair->name));
				strlcpy(pair->value, value, sizeof(pair->value));
				pair->operation = operation;
				rule.env_pair_count++;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "MODALIAS") == 0) {
				strlcpy(rule.modalias, value, sizeof(rule.modalias));
				rule.modalias_operation = operation;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, "IMPORT", sizeof("IMPORT")-1) == 0) {
				attr = get_key_attribute(key + sizeof("IMPORT")-1);
				if (attr && strstr(attr, "program")) {
					dbg("IMPORT will be executed");
					rule.import_exec = 1;
				} else if (attr && strstr(attr, "file")) {
					dbg("IMPORT will be included as file");
				} else {
					/* figure it out if it is executable */
					char file[PATH_SIZE];
					char *pos;
					struct stat stats;

					strlcpy(file, value, sizeof(file));
					pos = strchr(file, ' ');
					if (pos)
						pos[0] = '\0';
					dbg("IMPORT auto mode for '%s'", file);
					if (!lstat(file, &stats) && (stats.st_mode & S_IXUSR)) {
							dbg("IMPORT is executable, will be executed");
							rule.import_exec = 1;
					}
				}
				strlcpy(rule.import, value, sizeof(rule.import));
				rule.import_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "DRIVER") == 0) {
				strlcpy(rule.driver, value, sizeof(rule.driver));
				rule.driver_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "RESULT") == 0) {
				strlcpy(rule.result, value, sizeof(rule.result));
				rule.result_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "PROGRAM") == 0) {
				strlcpy(rule.program, value, sizeof(rule.program));
				rule.program_operation = operation;
				program_given = 1;
				valid = 1;
				continue;
			}

			if (strncasecmp(key, "NAME", sizeof("NAME")-1) == 0) {
				attr = get_key_attribute(key + sizeof("NAME")-1);
				if (attr != NULL) {
					if (strstr(attr, "all_partitions") != NULL) {
						dbg("creation of partition nodes requested");
						rule.partitions = DEFAULT_PARTITIONS_COUNT;
					}
					if (strstr(attr, "ignore_remove") != NULL) {
						dbg("remove event should be ignored");
						rule.ignore_remove = 1;
					}
				}
				rule.name_operation = operation;
				strlcpy(rule.name, value, sizeof(rule.name));
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "SYMLINK") == 0) {
				strlcpy(rule.symlink, value, sizeof(rule.symlink));
				rule.symlink_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "OWNER") == 0) {
				strlcpy(rule.owner, value, sizeof(rule.owner));
				rule.owner_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "GROUP") == 0) {
				strlcpy(rule.group, value, sizeof(rule.group));
				rule.group_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "MODE") == 0) {
				rule.mode = strtol(value, NULL, 8);
				rule.mode_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "RUN") == 0) {
				strlcpy(rule.run, value, sizeof(rule.run));
				rule.run_operation = operation;
				valid = 1;
				continue;
			}

			if (strcasecmp(key, "OPTIONS") == 0) {
				if (strstr(value, "last_rule") != NULL) {
					dbg("last rule to be applied");
					rule.last_rule = 1;
				}
				if (strstr(value, "ignore_device") != NULL) {
					dbg("device should be ignored");
					rule.ignore_device = 1;
				}
				if (strstr(value, "ignore_remove") != NULL) {
					dbg("remove event should be ignored");
					rule.ignore_remove = 1;
				}
				if (strstr(value, "all_partitions") != NULL) {
					dbg("creation of partition nodes requested");
					rule.partitions = DEFAULT_PARTITIONS_COUNT;
				}
				valid = 1;
				continue;
			}

			err("unknown key '%s'", key);
			goto error;
		}

		/* skip line if not any valid key was found */
		if (!valid)
			goto error;

		if ((rule.result[0] != '\0') && (program_given == 0)) {
			info("RESULT is only useful when PROGRAM is called in any rule before");
			goto error;
		}

		rule.config_line = lineno;
		strlcpy(rule.config_file, filename, sizeof(rule.config_file));
		retval = add_rule_to_list(&rule);
		if (retval) {
			dbg("add_rule_to_list returned with error %d", retval);
			continue;
error:
			err("parse error %s, line %d:%d, rule skipped",
			     filename, lineno, (int) (linepos - line));
		}
	}

	file_unmap(buf, bufsize);
	return retval;
}

static int rules_map(const char *filename)
{
	char *buf;
	size_t size;

	if (file_map(filename, &buf, &size))
		return -1;
	if (size == 0)
		return -1;
	rules_array = (struct udev_rule *) buf;
	rules_array_size = size;
	rules_count = size / sizeof(struct udev_rule);
	dbg("found %zi compiled rules", rules_count);

	return 0;
}

int udev_rules_init(void)
{
	char comp[PATH_SIZE];
	struct stat stats;
	int retval;

	strlcpy(comp, udev_rules_filename, sizeof(comp));
	strlcat(comp, ".compiled", sizeof(comp));
	if (stat(comp, &stats) == 0) {
		dbg("parse compiled rules '%s'", comp);
		return rules_map(comp);
	}

	if (stat(udev_rules_filename, &stats) != 0)
		return -1;

	if ((stats.st_mode & S_IFMT) != S_IFDIR) {
		dbg("parse single rules file '%s'", udev_rules_filename);
		retval = rules_parse(udev_rules_filename);
	} else {
		struct name_entry *name_loop, *name_tmp;
		LIST_HEAD(name_list);

		dbg("parse rules directory '%s'", udev_rules_filename);
		retval = add_matching_files(&name_list, udev_rules_filename, RULEFILE_SUFFIX);

		list_for_each_entry_safe(name_loop, name_tmp, &name_list, node) {
			rules_parse(name_loop->name);
			list_del(&name_loop->node);
		}
	}

	return retval;
}

void udev_rules_close(void)
{
	struct udev_rule *rule;
	struct udev_rule *temp_rule;

	if (rules_array)
		file_unmap(rules_array, rules_array_size);
	else
		list_for_each_entry_safe(rule, temp_rule, &rules_list, node) {
			list_del(&rule->node);
			free(rule);
		}
}
