/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>

#include "udev.h"

struct udev_rules {
	struct udev *udev;
	char *buf;
	size_t bufsize;
	int resolve_names;
};

struct udev_rules_iter {
	struct udev_rules *rules;
	size_t current;
};

enum key_operation {
	KEY_OP_UNSET,
	KEY_OP_MATCH,
	KEY_OP_NOMATCH,
	KEY_OP_ADD,
	KEY_OP_ASSIGN,
	KEY_OP_ASSIGN_FINAL,
};

struct key {
	enum key_operation operation;
	size_t val_off;
};

struct key_pair {
	struct key key;
	size_t key_name_off;
};

#define PAIRS_MAX		5
struct key_pairs {
	int count;
	struct key_pair keys[PAIRS_MAX];
};

enum import_type {
	IMPORT_UNSET,
	IMPORT_PROGRAM,
	IMPORT_FILE,
	IMPORT_PARENT,
};

enum escape_type {
	ESCAPE_UNSET,
	ESCAPE_NONE,
	ESCAPE_REPLACE,
};

struct udev_rule {
	struct key action;
	struct key devpath;
	struct key kernel;
	struct key subsystem;
	struct key driver;
	struct key_pairs attr;

	struct key kernels;
	struct key subsystems;
	struct key drivers;
	struct key_pairs attrs;

	struct key_pairs env;
	struct key program;
	struct key result;
	struct key import;
	enum import_type import_type;
	struct key test;
	mode_t test_mode_mask;
	struct key run;
	struct key wait_for;
	struct key label;
	struct key goto_label;
	size_t goto_rule_off;

	struct key name;
	struct key symlink;
	struct key symlink_match;
	struct key owner;
	struct key group;
	struct key mode;
	enum escape_type string_escape;

	unsigned int link_priority;
	int event_timeout;
	unsigned int partitions;
	unsigned int last_rule:1,
		     run_ignore_error:1,
		     ignore_device:1,
		     ignore_remove:1;

	size_t bufsize;
	char buf[];
};

static void udev_rules_iter_init(struct udev_rules_iter *iter, struct udev_rules *rules)
{
	dbg(rules->udev, "bufsize=%zi\n", rules->bufsize);
	iter->rules = rules;
	iter->current = 0;
}

static struct udev_rule *udev_rules_iter_next(struct udev_rules_iter *iter)
{
	struct udev_rules *rules;
	struct udev_rule *rule;

	rules = iter->rules;
	if (!rules)
		return NULL;

	dbg(rules->udev, "current=%zi\n", iter->current);
	if (iter->current >= rules->bufsize) {
		dbg(rules->udev, "no more rules\n");
		return NULL;
	}

	/* get next rule */
	rule = (struct udev_rule *) (rules->buf + iter->current);
	iter->current += sizeof(struct udev_rule) + rule->bufsize;

	return rule;
}

static struct udev_rule *udev_rules_iter_goto(struct udev_rules_iter *iter, size_t rule_off)
{
	struct udev_rules *rules = iter->rules;
	struct udev_rule *rule;

	dbg(rules->udev, "current=%zi\n", iter->current);
	iter->current = rule_off;
	rule = (struct udev_rule *) (rules->buf + iter->current);

	return rule;
}

static size_t find_label(const struct udev_rules_iter *iter, const char *label)
{
	struct udev_rule *rule;
	struct udev_rules *rules = iter->rules;
	size_t current = iter->current;

next:
	dbg(rules->udev, "current=%zi\n", current);
	if (current >= rules->bufsize) {
		dbg(rules->udev, "LABEL='%s' not found\n", label);
		return 0;
	}
	rule = (struct udev_rule *) (rules->buf + current);

	if (strcmp(&rule->buf[rule->label.val_off], label) != 0) {
		dbg(rules->udev, "moving forward, looking for label '%s'\n", label);
		current += sizeof(struct udev_rule) + rule->bufsize;
		goto next;
	}

	dbg(rules->udev, "found label '%s'\n", label);
	return current;
}

static int import_property_from_string(struct udev_device *dev, char *line)
{
	struct udev *udev = udev_device_get_udev(dev);
	char *key;
	char *val;
	size_t len;

	/* find key */
	key = line;
	while (isspace(key[0]))
		key++;

	/* comment or empty line */
	if (key[0] == '#' || key[0] == '\0')
		return -1;

	/* split key/value */
	val = strchr(key, '=');
	if (val == NULL)
		return -1;
	val[0] = '\0';
	val++;

	/* find value */
	while (isspace(val[0]))
		val++;

	/* terminate key */
	len = strlen(key);
	if (len == 0)
		return -1;
	while (isspace(key[len-1]))
		len--;
	key[len] = '\0';

	/* terminate value */
	len = strlen(val);
	if (len == 0)
		return -1;
	while (isspace(val[len-1]))
		len--;
	val[len] = '\0';

	if (len == 0)
		return -1;

	/* unquote */
	if (val[0] == '"' || val[0] == '\'') {
		if (val[len-1] != val[0]) {
			info(udev, "inconsistent quoting: '%s', skip\n", line);
			return -1;
		}
		val[len-1] = '\0';
		val++;
	}

	info(udev, "adding '%s'='%s'\n", key, val);

	/* handle device, renamed by external tool, returning new path */
	if (strcmp(key, "DEVPATH") == 0) {
		char syspath[UTIL_PATH_SIZE];

		info(udev, "updating devpath from '%s' to '%s'\n",
		     udev_device_get_devpath(dev), val);
		util_strlcpy(syspath, udev_get_sys_path(udev), sizeof(syspath));
		util_strlcat(syspath, val, sizeof(syspath));
		udev_device_set_syspath(dev, syspath);
	} else {
		struct udev_list_entry *entry;

		entry = udev_device_add_property(dev, key, val);
		/* store in db */
		udev_list_entry_set_flag(entry, 1);
	}
	return 0;
}

static int import_file_into_env(struct udev_device *dev, const char *filename)
{
	FILE *f;
	char line[UTIL_LINE_SIZE];

	f = fopen(filename, "r");
	if (f == NULL)
		return -1;
	while (fgets(line, sizeof(line), f) != NULL)
		import_property_from_string(dev, line);
	fclose(f);
	return 0;
}

static int import_program_into_env(struct udev_device *dev, const char *program)
{
	struct udev *udev = udev_device_get_udev(dev);
	char **envp;
	char result[2048];
	size_t reslen;
	char *line;

	envp = udev_device_get_properties_envp(dev);
	if (run_program(udev, program, envp, result, sizeof(result), &reslen) != 0)
		return -1;

	line = result;
	while (line != NULL) {
		char *pos;

		pos = strchr(line, '\n');
		if (pos != NULL) {
			pos[0] = '\0';
			pos = &pos[1];
		}
		import_property_from_string(dev, line);
		line = pos;
	}
	return 0;
}

static int import_parent_into_env(struct udev_device *dev, const char *filter)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_device *dev_parent;
	struct udev_list_entry *list_entry;

	dev_parent = udev_device_get_parent(dev);
	if (dev_parent == NULL)
		return -1;

	dbg(udev, "found parent '%s', get the node name\n", udev_device_get_syspath(dev_parent));
	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev_parent)) {
		const char *key = udev_list_entry_get_name(list_entry);
		const char *val = udev_list_entry_get_value(list_entry);

		if (fnmatch(filter, key, 0) == 0) {
			struct udev_list_entry *entry;

			dbg(udev, "import key '%s=%s'\n", key, val);
			entry = udev_device_add_property(dev, key, val);
			/* store in db */
			udev_list_entry_set_flag(entry, 1);
		}
	}
	return 0;
}

#define WAIT_LOOP_PER_SECOND		50
static int wait_for_file(struct udev_event *event, const char *file, int timeout)
{
	char filepath[UTIL_PATH_SIZE];
	char devicepath[UTIL_PATH_SIZE] = "";
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	/* a relative path is a device attribute */
	if (file[0] != '/') {
		util_strlcpy(devicepath, udev_get_sys_path(event->udev), sizeof(devicepath));
		util_strlcat(devicepath, udev_device_get_devpath(event->dev), sizeof(devicepath));

		util_strlcpy(filepath, devicepath, sizeof(filepath));
		util_strlcat(filepath, "/", sizeof(filepath));
		util_strlcat(filepath, file, sizeof(filepath));
		file = filepath;
	}

	dbg(event->udev, "will wait %i sec for '%s'\n", timeout, file);
	while (--loop) {
		/* lookup file */
		if (stat(file, &stats) == 0) {
			info(event->udev, "file '%s' appeared after %i loops\n", file, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		/* make sure, the device did not disappear in the meantime */
		if (devicepath[0] != '\0' && stat(devicepath, &stats) != 0) {
			info(event->udev, "device disappeared while waiting for '%s'\n", file);
			return -2;
		}
		info(event->udev, "wait for '%s' for %i mseconds\n", file, 1000 / WAIT_LOOP_PER_SECOND);
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	info(event->udev, "waiting for '%s' failed\n", file);
	return -1;
}

static int attr_subst_subdir(char *attr, size_t len)
{
	char *pos;
	int found = 0;

	pos = strstr(attr, "/*/");
	if (pos != NULL) {
		char str[UTIL_PATH_SIZE];
		DIR *dir;

		pos[1] = '\0';
		util_strlcpy(str, &pos[2], sizeof(str));
		dir = opendir(attr);
		if (dir != NULL) {
			struct dirent *dent;

			for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
				struct stat stats;

				if (dent->d_name[0] == '.')
					continue;
				util_strlcat(attr, dent->d_name, len);
				util_strlcat(attr, str, len);
				if (stat(attr, &stats) == 0) {
					found = 1;
					break;
				}
				pos[1] = '\0';
			}
			closedir(dir);
		}
		if (!found)
			util_strlcat(attr, str, len);
	}

	return found;
}

static char *key_val(struct udev_rule *rule, struct key *key)
{
	return rule->buf + key->val_off;
}

static char *key_pair_name(struct udev_rule *rule, struct key_pair *pair)
{
	return rule->buf + pair->key_name_off;
}

static int match_key(struct udev *udev, const char *key_name, struct udev_rule *rule, struct key *key, const char *val)
{
	char value[UTIL_PATH_SIZE];
	char *key_value;
	char *pos;
	int match = 0;

	if (key->operation != KEY_OP_MATCH &&
	    key->operation != KEY_OP_NOMATCH)
		return 0;

	if (val == NULL)
		val = "";

	/* look for a matching string, parts are separated by '|' */
	util_strlcpy(value, rule->buf + key->val_off, sizeof(value));
	key_value = value;
	dbg(udev, "key %s value='%s'\n", key_name, key_value);
	while (key_value != NULL) {
		pos = strchr(key_value, '|');
		if (pos != NULL) {
			pos[0] = '\0';
			pos = &pos[1];
		}

		dbg(udev, "match %s '%s' <-> '%s'\n", key_name, key_value, val);
		match = (fnmatch(key_value, val, 0) == 0);
		if (match)
			break;

		key_value = pos;
	}

	if (match && (key->operation == KEY_OP_MATCH)) {
		dbg(udev, "%s is true (matching value)\n", key_name);
		return 0;
	}
	if (!match && (key->operation == KEY_OP_NOMATCH)) {
		dbg(udev, "%s is true (non-matching value)\n", key_name);
		return 0;
	}
	return -1;
}

/* match a single rule against a given device and possibly its parent devices */
static int match_rule(struct udev_event *event, struct udev_rule *rule)
{
	struct udev_device *dev = event->dev;
	int i;

	if (match_key(event->udev, "ACTION", rule, &rule->action, udev_device_get_action(dev)))
		goto nomatch;

	if (match_key(event->udev, "KERNEL", rule, &rule->kernel, udev_device_get_sysname(dev)))
		goto nomatch;

	if (match_key(event->udev, "SUBSYSTEM", rule, &rule->subsystem, udev_device_get_subsystem(dev)))
		goto nomatch;

	if (match_key(event->udev, "DEVPATH", rule, &rule->devpath, udev_device_get_devpath(dev)))
		goto nomatch;

	if (match_key(event->udev, "DRIVER", rule, &rule->driver, udev_device_get_driver(dev)))
		goto nomatch;

	/* match NAME against a value assigned by an earlier rule */
	if (match_key(event->udev, "NAME", rule, &rule->name, event->name))
		goto nomatch;

	/* match against current list of symlinks */
	if (rule->symlink_match.operation == KEY_OP_MATCH ||
	    rule->symlink_match.operation == KEY_OP_NOMATCH) {
		size_t devlen = strlen(udev_get_dev_path(event->udev))+1;
		struct udev_list_entry *list_entry;
		int match = 0;

		udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
			const char *devlink;

			devlink =  &udev_list_entry_get_name(list_entry)[devlen];
			if (match_key(event->udev, "SYMLINK", rule, &rule->symlink_match, devlink) == 0) {
				match = 1;
				break;
			}
		}
		if (!match)
			goto nomatch;
	}

	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		/* we only check for matches, assignments will be handled later */
		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			struct udev_list_entry *list_entry;
			const char *key_name = key_pair_name(rule, pair);
			const char *value;

			list_entry = udev_device_get_properties_list_entry(event->dev);
			list_entry = udev_list_entry_get_by_name(list_entry, key_name);
			value = udev_list_entry_get_value(list_entry);
			if (value == NULL) {
				dbg(event->udev, "ENV{%s} is not set, treat as empty\n", key_name);
				value = "";
			}
			if (match_key(event->udev, "ENV", rule, &pair->key, value))
				goto nomatch;
		}
	}

	if (rule->test.operation == KEY_OP_MATCH ||
	    rule->test.operation == KEY_OP_NOMATCH) {
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;
		int match;

		util_strlcpy(filename, key_val(rule, &rule->test), sizeof(filename));
		udev_event_apply_format(event, filename, sizeof(filename));
		if (udev_event_apply_subsys_kernel(event, NULL, filename, sizeof(filename), 0) != 0)
			if (filename[0] != '/') {
				char tmp[UTIL_PATH_SIZE];

				util_strlcpy(tmp, udev_device_get_syspath(dev), sizeof(tmp));
				util_strlcat(tmp, "/", sizeof(tmp));
				util_strlcat(tmp, filename, sizeof(tmp));
				util_strlcpy(filename, tmp, sizeof(filename));
			}

		attr_subst_subdir(filename, sizeof(filename));

		match = (stat(filename, &statbuf) == 0);
		info(event->udev, "'%s' %s", filename, match ? "exists\n" : "does not exist\n");
		if (match && rule->test_mode_mask > 0) {
			match = ((statbuf.st_mode & rule->test_mode_mask) > 0);
			info(event->udev, "'%s' has mode=%#o and %s %#o\n", filename, statbuf.st_mode,
			     match ? "matches" : "does not match",
			     rule->test_mode_mask);
		}
		if (match && rule->test.operation == KEY_OP_NOMATCH)
			goto nomatch;
		if (!match && rule->test.operation == KEY_OP_MATCH)
			goto nomatch;
		dbg(event->udev, "TEST key is true\n");
	}

	if (rule->wait_for.operation != KEY_OP_UNSET) {
		char filename[UTIL_PATH_SIZE];
		int found;

		util_strlcpy(filename, key_val(rule, &rule->wait_for), sizeof(filename));
		udev_event_apply_format(event, filename, sizeof(filename));
		found = (wait_for_file(event, filename, 10) == 0);
		if (!found && (rule->wait_for.operation != KEY_OP_NOMATCH))
			goto nomatch;
	}

	/* check for matching sysfs attribute pairs */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			char attr[UTIL_PATH_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *key_value = key_val(rule, &pair->key);
			char value[UTIL_NAME_SIZE] = "";
			size_t len;

			util_strlcpy(attr, key_name, sizeof(attr));
			udev_event_apply_subsys_kernel(event, attr, value, sizeof(value), 1);

			if (value[0]=='\0') {
				const char *val;

				val = udev_device_get_attr_value(dev, key_name);
				if (val != NULL)
					util_strlcpy(value, val, sizeof(value));
			}

			if (value[0]=='\0')
				goto nomatch;

			/* strip trailing whitespace of value, if not asked to match for it */
			len = strlen(key_value);
			if (len > 0 && !isspace(key_value[len-1])) {
				len = strlen(value);
				while (len > 0 && isspace(value[--len]))
					value[len] = '\0';
				dbg(event->udev, "removed trailing whitespace from '%s'\n", value);
			}

			if (match_key(event->udev, "ATTR", rule, &pair->key, value))
				goto nomatch;
		}
	}

	/* walk up the chain of parent devices and find a match */
	event->dev_parent = dev;
	while (1) {
		/* check for matching kernel device name */
		if (match_key(event->udev, "KERNELS", rule,
			      &rule->kernels, udev_device_get_sysname(event->dev_parent)))
			goto try_parent;

		/* check for matching subsystem value */
		if (match_key(event->udev, "SUBSYSTEMS", rule,
			      &rule->subsystems, udev_device_get_subsystem(event->dev_parent)))
			goto try_parent;

		/* check for matching driver */
		if (match_key(event->udev, "DRIVERS", rule,
			      &rule->drivers, udev_device_get_driver(event->dev_parent)))
			goto try_parent;

		/* check for matching sysfs attribute pairs */
		for (i = 0; i < rule->attrs.count; i++) {
			struct key_pair *pair = &rule->attrs.keys[i];

			if (pair->key.operation == KEY_OP_MATCH ||
			    pair->key.operation == KEY_OP_NOMATCH) {
				const char *key_name = key_pair_name(rule, pair);
				const char *key_value = key_val(rule, &pair->key);
				const char *val;
				char value[UTIL_NAME_SIZE];
				size_t len;

				val = udev_device_get_attr_value(event->dev_parent, key_name);
				if (val == NULL)
					val = udev_device_get_attr_value(dev, key_name);
				if (val == NULL)
					goto try_parent;
				util_strlcpy(value, val, sizeof(value));

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(key_value);
				if (len > 0 && !isspace(key_value[len-1])) {
					len = strlen(value);
					while (len > 0 && isspace(value[--len]))
						value[len] = '\0';
					dbg(event->udev, "removed trailing whitespace from '%s'\n", value);
				}

				if (match_key(event->udev, "ATTRS", rule, &pair->key, value))
					goto try_parent;
			}
		}

		/* found matching device  */
		break;
try_parent:
		/* move to parent device */
		dbg(event->udev, "try parent sysfs device\n");
		event->dev_parent = udev_device_get_parent(event->dev_parent);
		if (event->dev_parent == NULL)
			goto nomatch;
		dbg(event->udev, "looking at dev_parent->devpath='%s'\n",
		    udev_device_get_syspath(event->dev_parent));
	}

	/* execute external program */
	if (rule->program.operation != KEY_OP_UNSET) {
		char program[UTIL_PATH_SIZE];
		char **envp;
		char result[UTIL_PATH_SIZE];

		util_strlcpy(program, key_val(rule, &rule->program), sizeof(program));
		udev_event_apply_format(event, program, sizeof(program));
		envp = udev_device_get_properties_envp(dev);
		if (run_program(event->udev, program, envp, result, sizeof(result), NULL) != 0) {
			dbg(event->udev, "PROGRAM is false\n");
			event->program_result[0] = '\0';
			if (rule->program.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else {
			int count;

			dbg(event->udev, "PROGRAM matches\n");
			util_remove_trailing_chars(result, '\n');
			if (rule->string_escape == ESCAPE_UNSET ||
			    rule->string_escape == ESCAPE_REPLACE) {
				count = util_replace_chars(result, ALLOWED_CHARS_INPUT);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
			}
			dbg(event->udev, "result is '%s'\n", result);
			util_strlcpy(event->program_result, result, sizeof(event->program_result));
			dbg(event->udev, "PROGRAM returned successful\n");
			if (rule->program.operation == KEY_OP_NOMATCH)
				goto nomatch;
		}
		dbg(event->udev, "PROGRAM key is true\n");
	}

	/* check for matching result of external program */
	if (match_key(event->udev, "RESULT", rule, &rule->result, event->program_result))
		goto nomatch;

	/* import variables returned from program or or file into properties */
	if (rule->import.operation != KEY_OP_UNSET) {
		char import[UTIL_PATH_SIZE];
		int rc = -1;

		util_strlcpy(import, key_val(rule, &rule->import), sizeof(import));
		udev_event_apply_format(event, import, sizeof(import));
		dbg(event->udev, "check for IMPORT import='%s'\n", import);
		if (rule->import_type == IMPORT_PROGRAM) {
			rc = import_program_into_env(event->dev, import);
		} else if (rule->import_type == IMPORT_FILE) {
			dbg(event->udev, "import file import='%s'\n", import);
			rc = import_file_into_env(event->dev, import);
		} else if (rule->import_type == IMPORT_PARENT) {
			dbg(event->udev, "import parent import='%s'\n", import);
			rc = import_parent_into_env(event->dev, import);
		}
		if (rc != 0) {
			dbg(event->udev, "IMPORT failed\n");
			if (rule->import.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else
			dbg(event->udev, "IMPORT '%s' imported\n", key_val(rule, &rule->import));
		dbg(event->udev, "IMPORT key is true\n");
	}

	/* rule matches, if we have ENV assignments export it */
	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			char temp_value[UTIL_NAME_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *value = key_val(rule, &pair->key);

			/* make sure we don't write to the same string we possibly read from */
			util_strlcpy(temp_value, value, sizeof(temp_value));
			udev_event_apply_format(event, temp_value, sizeof(temp_value));

			if (temp_value[0] != '\0') {
				struct udev_list_entry *entry;

				info(event->udev, "set ENV '%s=%s'\n", key_name, temp_value);
				entry = udev_device_add_property(dev, key_name, temp_value);
				/* store in db */
				udev_list_entry_set_flag(entry, 1);
			}
		}
	}

	/* if we have ATTR assignments, write value to sysfs file */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			char attr[UTIL_PATH_SIZE];
			char value[UTIL_NAME_SIZE];
			FILE *f;

			util_strlcpy(attr, key_name, sizeof(attr));
			if (udev_event_apply_subsys_kernel(event, key_name, attr, sizeof(attr), 0) != 0) {
				util_strlcpy(attr, udev_device_get_syspath(dev), sizeof(attr));
				util_strlcat(attr, "/", sizeof(attr));
				util_strlcat(attr, key_name, sizeof(attr));
			}

			attr_subst_subdir(attr, sizeof(attr));

			util_strlcpy(value, key_val(rule, &pair->key), sizeof(value));
			udev_event_apply_format(event, value, sizeof(value));
			info(event->udev, "writing '%s' to sysfs file '%s'\n", value, attr);
			f = fopen(attr, "w");
			if (f != NULL) {
				if (!event->test)
					if (fprintf(f, "%s", value) <= 0)
						err(event->udev, "error writing ATTR{%s}: %m\n", attr);
				fclose(f);
			} else
				err(event->udev, "error opening ATTR{%s} for writing: %m\n", attr);
		}
	}
	return 0;

nomatch:
	return -1;
}

int udev_rules_get_name(struct udev_rules *rules, struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	struct udev_rules_iter iter;
	struct udev_rule *rule;
	int name_set = 0;

	dbg(event->udev, "device: '%s'\n", udev_device_get_syspath(dev));

	/* look for a matching rule to apply */
	udev_rules_iter_init(&iter, rules);
	while (1) {
		rule = udev_rules_iter_next(&iter);
		if (rule == NULL)
			break;

		if (name_set &&
		    (rule->name.operation == KEY_OP_ASSIGN ||
		     rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		     rule->name.operation == KEY_OP_ADD)) {
			dbg(event->udev, "node name already set, rule ignored\n");
			continue;
		}

		dbg(event->udev, "process rule\n");
		if (match_rule(event, rule) == 0) {
			/* apply options */
			if (rule->ignore_device) {
				info(event->udev, "rule applied, '%s' is ignored\n", udev_device_get_sysname(dev));
				event->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev_device_set_ignore_remove(dev, 1);
				dbg(event->udev, "remove event should be ignored\n");
			}
			if (rule->link_priority != 0) {
				udev_device_set_devlink_priority(dev, rule->link_priority);
				info(event->udev, "devlink_priority=%i\n", rule->link_priority);
			}
			if (rule->event_timeout >= 0) {
				udev_device_set_event_timeout(dev, rule->event_timeout);
				info(event->udev, "event_timeout=%i\n", rule->event_timeout);
			}
			/* apply all_partitions option only at a disk device */
			if (rule->partitions > 0 &&
			    strcmp(udev_device_get_subsystem(dev), "block") == 0 &&
			    udev_device_get_sysnum(dev) == NULL) {
				udev_device_set_num_fake_partitions(dev, rule->partitions);
				dbg(event->udev, "creation of partition nodes requested\n");
			}

			/* apply permissions */
			if (!event->mode_final && rule->mode.operation != KEY_OP_UNSET) {
				if (rule->mode.operation == KEY_OP_ASSIGN_FINAL)
					event->mode_final = 1;
				char buf[20];
				util_strlcpy(buf, key_val(rule, &rule->mode), sizeof(buf));
				udev_event_apply_format(event, buf, sizeof(buf));
				event->mode = strtol(buf, NULL, 8);
				dbg(event->udev, "applied mode=%#o to '%s'\n",
				    event->mode, udev_device_get_sysname(dev));
			}
			if (!event->owner_final && rule->owner.operation != KEY_OP_UNSET) {
				if (rule->owner.operation == KEY_OP_ASSIGN_FINAL)
					event->owner_final = 1;
				util_strlcpy(event->owner, key_val(rule, &rule->owner), sizeof(event->owner));
				udev_event_apply_format(event, event->owner, sizeof(event->owner));
				dbg(event->udev, "applied owner='%s' to '%s'\n",
				    event->owner, udev_device_get_sysname(dev));
			}
			if (!event->group_final && rule->group.operation != KEY_OP_UNSET) {
				if (rule->group.operation == KEY_OP_ASSIGN_FINAL)
					event->group_final = 1;
				util_strlcpy(event->group, key_val(rule, &rule->group), sizeof(event->group));
				udev_event_apply_format(event, event->group, sizeof(event->group));
				dbg(event->udev, "applied group='%s' to '%s'\n",
				    event->group, udev_device_get_sysname(dev));
			}

			/* collect symlinks */
			if (!event->devlink_final &&
			    (rule->symlink.operation == KEY_OP_ASSIGN ||
			     rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
			     rule->symlink.operation == KEY_OP_ADD)) {
				char temp[UTIL_PATH_SIZE];
				char filename[UTIL_PATH_SIZE];
				char *pos, *next;
				int count = 0;

				if (rule->symlink.operation == KEY_OP_ASSIGN_FINAL)
					event->devlink_final = 1;
				if (rule->symlink.operation == KEY_OP_ASSIGN ||
				    rule->symlink.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset symlink list\n");
					udev_device_cleanup_devlinks_list(dev);
				}
				/* allow  multiple symlinks separated by spaces */
				util_strlcpy(temp, key_val(rule, &rule->symlink), sizeof(temp));
				udev_event_apply_format(event, temp, sizeof(temp));
				if (rule->string_escape == ESCAPE_UNSET)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE " ");
				else if (rule->string_escape == ESCAPE_REPLACE)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
				dbg(event->udev, "rule applied, added symlink(s) '%s'\n", temp);
				pos = temp;
				while (isspace(pos[0]))
					pos++;
				next = strchr(pos, ' ');
				while (next) {
					next[0] = '\0';
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(dev, filename);
					while (isspace(next[1]))
						next++;
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				if (pos[0] != '\0') {
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(dev, filename);
				}
			}

			/* set name, later rules with name set will be ignored */
			if (rule->name.operation == KEY_OP_ASSIGN ||
			    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
			    rule->name.operation == KEY_OP_ADD) {
				int count;

				name_set = 1;
				util_strlcpy(event->name, key_val(rule, &rule->name), sizeof(event->name));
				udev_event_apply_format(event, event->name, sizeof(event->name));
				if (rule->string_escape == ESCAPE_UNSET ||
				    rule->string_escape == ESCAPE_REPLACE) {
					count = util_replace_chars(event->name, ALLOWED_CHARS_FILE);
					if (count > 0)
						info(event->udev, "%i character(s) replaced\n", count);
				}

				info(event->udev, "rule applied, '%s' becomes '%s'\n",
				     udev_device_get_sysname(dev), event->name);
				if (strcmp(udev_device_get_subsystem(dev), "net") != 0)
					dbg(event->udev, "'%s' owner='%s', group='%s', mode=%#o partitions=%i\n",
					    event->name, event->owner, event->group, event->mode,
					    udev_device_get_num_fake_partitions(dev));
			}

			if (!event->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct udev_list_entry *list_entry;

				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					event->run_final = 1;
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset run list\n");
					udev_list_cleanup_entries(event->udev, &event->run_list);
				}
				dbg(event->udev, "add run '%s'\n", key_val(rule, &rule->run));
				list_entry = udev_list_entry_add(event->udev, &event->run_list,
								 key_val(rule, &rule->run), NULL, 1, 0);
				if (rule->run_ignore_error && list_entry != NULL)
					udev_list_entry_set_flag(list_entry, 1);
			}

			if (rule->last_rule) {
				dbg(event->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(event->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_goto(&iter, rule->goto_rule_off);
			}
		}
	}

	if (!name_set) {
		info(event->udev, "no node name set, will use kernel name '%s'\n",
		     udev_device_get_sysname(dev));
		util_strlcpy(event->name, udev_device_get_sysname(dev), sizeof(event->name));
	}

	if (event->tmp_node[0] != '\0') {
		dbg(event->udev, "removing temporary device node\n");
		unlink_secure(event->udev, event->tmp_node);
		event->tmp_node[0] = '\0';
	}
	return 0;
}

int udev_rules_get_run(struct udev_rules *rules, struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	struct udev_rules_iter iter;
	struct udev_rule *rule;

	dbg(event->udev, "sysname: '%s'\n", udev_device_get_sysname(dev));

	/* look for a matching rule to apply */
	udev_rules_iter_init(&iter, rules);
	while (1) {
		rule = udev_rules_iter_next(&iter);
		if (rule == NULL)
			break;

		dbg(event->udev, "process rule\n");
		if (rule->name.operation == KEY_OP_ASSIGN ||
		    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->name.operation == KEY_OP_ADD ||
		    rule->symlink.operation == KEY_OP_ASSIGN ||
		    rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->symlink.operation == KEY_OP_ADD ||
		    rule->mode.operation != KEY_OP_UNSET ||
		    rule->owner.operation != KEY_OP_UNSET || rule->group.operation != KEY_OP_UNSET) {
			dbg(event->udev, "skip rule that names a device\n");
			continue;
		}

		if (match_rule(event, rule) == 0) {
			if (rule->ignore_device) {
				info(event->udev, "rule applied, '%s' is ignored\n", udev_device_get_sysname(dev));
				event->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev_device_set_ignore_remove(dev, 1);
				dbg(event->udev, "remove event should be ignored\n");
			}

			if (!event->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct udev_list_entry *list_entry;

				if (rule->run.operation == KEY_OP_ASSIGN ||
				    rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset run list\n");
					udev_list_cleanup_entries(event->udev, &event->run_list);
				}
				dbg(event->udev, "add run '%s'\n", key_val(rule, &rule->run));
				list_entry = udev_list_entry_add(event->udev, &event->run_list,
								 key_val(rule, &rule->run), NULL, 1, 0);
				if (rule->run_ignore_error && list_entry != NULL)
					udev_list_entry_set_flag(list_entry, 1);
				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					break;
			}

			if (rule->last_rule) {
				dbg(event->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(event->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_goto(&iter, rule->goto_rule_off);
			}
		}
	}

	return 0;
}

static int get_key(struct udev_rules *rules, char **line, char **key, enum key_operation *operation, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (linepos == NULL && linepos[0] == '\0')
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
		linepos++;

	/* get the key */
	if (linepos[0] == '\0')
		return -1;
	*key = linepos;

	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
		if ((linepos[0] == '+') || (linepos[0] == '!') || (linepos[0] == ':'))
			if (linepos[1] == '=')
				break;
	}

	/* remember end of key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get operation type */
	if (linepos[0] == '=' && linepos[1] == '=') {
		*operation = KEY_OP_MATCH;
		linepos += 2;
		dbg(rules->udev, "match:\n");
	} else if (linepos[0] == '!' && linepos[1] == '=') {
		*operation = KEY_OP_NOMATCH;
		linepos += 2;
		dbg(rules->udev, "nomatch:\n");
	} else if (linepos[0] == '+' && linepos[1] == '=') {
		*operation = KEY_OP_ADD;
		linepos += 2;
		dbg(rules->udev, "add:\n");
	} else if (linepos[0] == '=') {
		*operation = KEY_OP_ASSIGN;
		linepos++;
		dbg(rules->udev, "assign:\n");
	} else if (linepos[0] == ':' && linepos[1] == '=') {
		*operation = KEY_OP_ASSIGN_FINAL;
		linepos += 2;
		dbg(rules->udev, "assign_final:\n");
	} else
		return -1;

	/* terminate key */
	temp[0] = '\0';

	/* skip whitespace after operator */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

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
	dbg(rules->udev, "'%s'-'%s'\n", *key, *value);

	/* move line to next key */
	*line = temp;
	return 0;
}

/* extract possible KEY{attr} */
static char *get_key_attribute(struct udev_rules *rules, char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			err(rules->udev, "missing closing brace for format\n");
			return NULL;
		}
		pos[0] = '\0';
		dbg(rules->udev, "attribute='%s'\n", attr);
		return attr;
	}

	return NULL;
}

static int add_rule_key(struct udev_rule *rule, struct key *key,
			enum key_operation operation, const char *value)
{
	size_t val_len = strnlen(value, UTIL_PATH_SIZE);

	key->operation = operation;

	key->val_off = rule->bufsize;
	util_strlcpy(rule->buf + rule->bufsize, value, val_len+1);
	rule->bufsize += val_len+1;

	return 0;
}

static int add_rule_key_pair(struct udev_rules *rules, struct udev_rule *rule, struct key_pairs *pairs,
			     enum key_operation operation, const char *key, const char *value)
{
	size_t key_len = strnlen(key, UTIL_PATH_SIZE);

	if (pairs->count >= PAIRS_MAX) {
		err(rules->udev, "skip, too many keys of the same type in a single rule\n");
		return -1;
	}

	add_rule_key(rule, &pairs->keys[pairs->count].key, operation, value);

	/* add the key-name of the pair */
	pairs->keys[pairs->count].key_name_off = rule->bufsize;
	util_strlcpy(rule->buf + rule->bufsize, key, key_len+1);
	rule->bufsize += key_len+1;

	pairs->count++;

	return 0;
}

static int add_to_rules(struct udev_rules *rules, char *line, const char *filename, unsigned int lineno)
{
	char buf[sizeof(struct udev_rule) + UTIL_LINE_SIZE];
	struct udev_rule *rule;
	size_t rule_size;
	int valid;
	char *linepos;
	char *attr;
	size_t padding;
	int physdev = 0;

	memset(buf, 0x00, sizeof(buf));
	rule = (struct udev_rule *) buf;
	rule->event_timeout = -1;
	linepos = line;
	valid = 0;

	/* get all the keys */
	while (1) {
		char *key;
		char *value;
		enum key_operation operation = KEY_OP_UNSET;

		if (get_key(rules, &linepos, &key, &operation, &value) != 0)
			break;

		if (strcasecmp(key, "ACTION") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ACTION operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->action, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DEVPATH") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DEVPATH operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->devpath, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNEL") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNEL operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernel, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEM") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEM operation\n");
				goto invalid;
			}
			/* bus, class, subsystem events should all be the same */
			if (strcmp(value, "subsystem") == 0 ||
			    strcmp(value, "bus") == 0 ||
			    strcmp(value, "class") == 0) {
				if (strcmp(value, "bus") == 0 || strcmp(value, "class") == 0)
					err(rules->udev, "'%s' must be specified as 'subsystem' \n"
					    "please fix it in %s:%u", value, filename, lineno);
				add_rule_key(rule, &rule->subsystem, operation, "subsystem|class|bus");
			} else
				add_rule_key(rule, &rule->subsystem, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVER") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVER operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->driver, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTR{", sizeof("ATTR{")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("ATTR")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTR attribute\n");
				goto invalid;
			}
			if (add_rule_key_pair(rules, rule, &rule->attr, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNELS") == 0 ||
		    strcasecmp(key, "ID") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNELS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernels, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEMS") == 0 ||
		    strcasecmp(key, "BUS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEMS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->subsystems, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVERS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVERS operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->drivers, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTRS{", sizeof("ATTRS{")-1) == 0 ||
		    strncasecmp(key, "SYSFS{", sizeof("SYSFS{")-1) == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ATTRS operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules, key + sizeof("ATTRS")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTRS attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "device/", 7) == 0)
				err(rules->udev, "the 'device' link may not be available in a future kernel, "
				    "please fix it in %s:%u", filename, lineno);
			else if (strstr(attr, "../") != NULL)
				err(rules->udev, "do not reference parent sysfs directories directly, "
				    "it may break with a future kernel, please fix it in %s:%u", filename, lineno);
			if (add_rule_key_pair(rules, rule, &rule->attrs, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ENV{", sizeof("ENV{")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("ENV")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ENV attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "PHYSDEV", 7) == 0)
				physdev = 1;
			if (add_rule_key_pair(rules, rule, &rule->env, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "PROGRAM") == 0) {
			add_rule_key(rule, &rule->program, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "RESULT") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid RESULT operation\n");
				goto invalid;
			}
			add_rule_key(rule, &rule->result, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "IMPORT", sizeof("IMPORT")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("IMPORT")-1);
			if (attr != NULL && strstr(attr, "program")) {
				dbg(rules->udev, "IMPORT will be executed\n");
				rule->import_type  = IMPORT_PROGRAM;
			} else if (attr != NULL && strstr(attr, "file")) {
				dbg(rules->udev, "IMPORT will be included as file\n");
				rule->import_type  = IMPORT_FILE;
			} else if (attr != NULL && strstr(attr, "parent")) {
				dbg(rules->udev, "IMPORT will include the parent values\n");
				rule->import_type = IMPORT_PARENT;
			} else {
				/* figure it out if it is executable */
				char file[UTIL_PATH_SIZE];
				char *pos;
				struct stat statbuf;

				util_strlcpy(file, value, sizeof(file));
				pos = strchr(file, ' ');
				if (pos)
					pos[0] = '\0';

				/* allow programs in /lib/udev called without the path */
				if (strchr(file, '/') == NULL) {
					util_strlcpy(file, UDEV_PREFIX "/lib/udev/", sizeof(file));
					util_strlcat(file, value, sizeof(file));
					pos = strchr(file, ' ');
					if (pos)
						pos[0] = '\0';
				}

				dbg(rules->udev, "IMPORT auto mode for '%s'\n", file);
				if (!lstat(file, &statbuf) && (statbuf.st_mode & S_IXUSR)) {
					dbg(rules->udev, "IMPORT is executable, will be executed (autotype)\n");
					rule->import_type  = IMPORT_PROGRAM;
				} else {
					dbg(rules->udev, "IMPORT is not executable, will be included as file (autotype)\n");
					rule->import_type  = IMPORT_FILE;
				}
			}
			add_rule_key(rule, &rule->import, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "TEST", sizeof("TEST")-1) == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid TEST operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules, key + sizeof("TEST")-1);
			if (attr != NULL)
				rule->test_mode_mask = strtol(attr, NULL, 8);
			add_rule_key(rule, &rule->test, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "RUN", sizeof("RUN")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("RUN")-1);
			if (attr != NULL) {
				if (strstr(attr, "ignore_error"))
					rule->run_ignore_error = 1;
			}
			add_rule_key(rule, &rule->run, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "WAIT_FOR") == 0 || strcasecmp(key, "WAIT_FOR_SYSFS") == 0) {
			add_rule_key(rule, &rule->wait_for, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "LABEL") == 0) {
			add_rule_key(rule, &rule->label, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "GOTO") == 0) {
			add_rule_key(rule, &rule->goto_label, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "NAME", sizeof("NAME")-1) == 0) {
			attr = get_key_attribute(rules, key + sizeof("NAME")-1);
			if (attr != NULL) {
				if (strstr(attr, "all_partitions") != NULL) {
					dbg(rules->udev, "creation of partition nodes requested\n");
					rule->partitions = DEFAULT_FAKE_PARTITIONS_COUNT;
				}
				if (strstr(attr, "ignore_remove") != NULL) {
					dbg(rules->udev, "remove event should be ignored\n");
					rule->ignore_remove = 1;
				}
			}
			if (value[0] == '\0')
				dbg(rules->udev, "name empty, node creation supressed\n");
			add_rule_key(rule, &rule->name, operation, value);
			continue;
		}

		if (strcasecmp(key, "SYMLINK") == 0) {
			if (operation == KEY_OP_MATCH ||
			    operation == KEY_OP_NOMATCH)
				add_rule_key(rule, &rule->symlink_match, operation, value);
			else
				add_rule_key(rule, &rule->symlink, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OWNER") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char owner[32];
					uid_t uid = lookup_user(rules->udev, value);
					dbg(rules->udev, "replacing username='%s' by id=%i\n", value, uid);
					sprintf(owner, "%u", (unsigned int) uid);
					add_rule_key(rule, &rule->owner, operation, owner);
					continue;
				}
			}

			add_rule_key(rule, &rule->owner, operation, value);
			continue;
		}

		if (strcasecmp(key, "GROUP") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char group[32];
					gid_t gid = lookup_group(rules->udev, value);
					dbg(rules->udev, "replacing groupname='%s' by id=%i\n", value, gid);
					sprintf(group, "%u", (unsigned int) gid);
					add_rule_key(rule, &rule->group, operation, group);
					continue;
				}
			}

			add_rule_key(rule, &rule->group, operation, value);
			continue;
		}

		if (strcasecmp(key, "MODE") == 0) {
			add_rule_key(rule, &rule->mode, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OPTIONS") == 0) {
			const char *pos;

			if (strstr(value, "last_rule") != NULL) {
				dbg(rules->udev, "last rule to be applied\n");
				rule->last_rule = 1;
			}
			if (strstr(value, "ignore_device") != NULL) {
				dbg(rules->udev, "device should be ignored\n");
				rule->ignore_device = 1;
			}
			if (strstr(value, "ignore_remove") != NULL) {
				dbg(rules->udev, "remove event should be ignored\n");
				rule->ignore_remove = 1;
			}
			pos = strstr(value, "link_priority=");
			if (pos != NULL) {
				rule->link_priority = atoi(&pos[strlen("link_priority=")]);
				dbg(rules->udev, "link priority=%i\n", rule->link_priority);
			}
			pos = strstr(value, "event_timeout=");
			if (pos != NULL) {
				rule->event_timeout = atoi(&pos[strlen("event_timeout=")]);
				dbg(rules->udev, "event timout=%i\n", rule->event_timeout);
			}
			pos = strstr(value, "string_escape=");
			if (pos != NULL) {
				pos = &pos[strlen("string_escape=")];
				if (strncmp(pos, "none", strlen("none")) == 0)
					rule->string_escape = ESCAPE_NONE;
				else if (strncmp(pos, "replace", strlen("replace")) == 0)
					rule->string_escape = ESCAPE_REPLACE;
			}
			if (strstr(value, "all_partitions") != NULL) {
				dbg(rules->udev, "creation of partition nodes requested\n");
				rule->partitions = DEFAULT_FAKE_PARTITIONS_COUNT;
			}
			valid = 1;
			continue;
		}

		err(rules->udev, "unknown key '%s' in %s:%u\n", key, filename, lineno);
	}

	if (physdev && rule->wait_for.operation == KEY_OP_UNSET)
		err(rules->udev, "PHYSDEV* values are deprecated and will be removed from a future kernel, \n"
		    "please fix it in %s:%u", filename, lineno);

	/* skip line if not any valid key was found */
	if (!valid)
		goto invalid;

	/* grow buffer and add rule */
	rule_size = sizeof(struct udev_rule) + rule->bufsize;
	padding = (sizeof(size_t) - rule_size % sizeof(size_t)) % sizeof(size_t);
	dbg(rules->udev, "add %zi padding bytes\n", padding);
	rule_size += padding;
	rule->bufsize += padding;

	rules->buf = realloc(rules->buf, rules->bufsize + rule_size);
	if (!rules->buf) {
		err(rules->udev, "realloc failed\n");
		goto exit;
	}
	dbg(rules->udev, "adding rule to offset %zi\n", rules->bufsize);
	memcpy(rules->buf + rules->bufsize, rule, rule_size);
	rules->bufsize += rule_size;
exit:
	return 0;

invalid:
	err(rules->udev, "invalid rule '%s:%u'\n", filename, lineno);
	return -1;
}

static int parse_file(struct udev_rules *rules, const char *filename)
{
	FILE *f;
	char line[UTIL_LINE_SIZE];
	size_t start;
	struct udev_rule *rule;
	struct udev_rules_iter iter;

	start = rules->bufsize;
	info(rules->udev, "reading '%s' as rules file\n", filename);

	f = fopen(filename, "r");
	if (f == NULL)
		return -1;

	while(fgets(line, sizeof(line), f) != NULL) {
		int line_nr = 0;
		char *key;
		size_t len;

		/* skip whitespace */
		line_nr++;
		key = line;
		while (isspace(key[0]))
			key++;

		/* comment */
		if (key[0] == '#')
			continue;

		len = strlen(line);
		if (len < 3)
			continue;

		/* continue reading if backslash+newline is found */
		while (line[len-2] == '\\') {
			if (fgets(&line[len-2], (sizeof(line)-len)+2, f) == NULL)
				break;
			line_nr++;
			len = strlen(line);
		}

		if (len+1 >= sizeof(line)) {
			err(rules->udev, "line too long '%s':%u, ignored\n", filename, line_nr);
			continue;
		}
		add_to_rules(rules, key, filename, line_nr);
	}
	fclose(f);

	/* compute all goto targets within this file */
	udev_rules_iter_init(&iter, rules);
	udev_rules_iter_goto(&iter, start);
	while((rule = udev_rules_iter_next(&iter))) {
		if (rule->goto_label.operation != KEY_OP_UNSET) {
			char *goto_label = &rule->buf[rule->goto_label.val_off];

			dbg(rules->udev, "resolving goto label '%s'\n", goto_label);
			rule->goto_rule_off = find_label(&iter, goto_label);
			if (rule->goto_rule_off == 0) {
				err(rules->udev, "ignore goto to nonexistent label '%s' in '%s'\n",
				    goto_label, filename);
				rule->goto_rule_off = iter.current;
			}
		}
	}
	return 0;
}

static int add_matching_files(struct udev *udev, struct udev_list_node *file_list, const char *dirname, const char *suffix)
{
	struct dirent *ent;
	DIR *dir;
	char filename[UTIL_PATH_SIZE];

	dbg(udev, "open directory '%s'\n", dirname);
	dir = opendir(dirname);
	if (dir == NULL) {
		err(udev, "unable to open '%s': %m\n", dirname);
		return -1;
	}

	while (1) {
		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;

		if ((ent->d_name[0] == '.') || (ent->d_name[0] == '#'))
			continue;

		/* look for file matching with specified suffix */
		if (suffix != NULL) {
			const char *ext;

			ext = strrchr(ent->d_name, '.');
			if (ext == NULL)
				continue;
			if (strcmp(ext, suffix) != 0)
				continue;
		}
		dbg(udev, "put file '%s/%s' into list\n", dirname, ent->d_name);

		snprintf(filename, sizeof(filename), "%s/%s", dirname, ent->d_name);
		filename[sizeof(filename)-1] = '\0';
		udev_list_entry_add(udev, file_list, filename, NULL, 1, 1);
	}

	closedir(dir);
	return 0;
}

struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names)
{
	struct udev_rules *rules;
	struct stat statbuf;
	char filename[PATH_MAX];
	struct udev_list_node file_list;
	struct udev_list_entry *file_loop, *file_tmp;

	rules = malloc(sizeof(struct udev_rules));
	if (rules == NULL)
		return rules;
	memset(rules, 0x00, sizeof(struct udev_rules));
	rules->udev = udev;
	rules->resolve_names = resolve_names;
	udev_list_init(&file_list);

	if (udev_get_rules_path(udev) != NULL) {
		/* custom rules location for testing */
		add_matching_files(udev, &file_list, udev_get_rules_path(udev), ".rules");
	} else {
		struct udev_list_node sort_list;
		struct udev_list_entry *sort_loop, *sort_tmp;

		/* read user/custom rules */
		add_matching_files(udev, &file_list, SYSCONFDIR "/udev/rules.d", ".rules");

		/* read dynamic/temporary rules */
		util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		util_strlcat(filename, "/.udev/rules.d", sizeof(filename));
		if (stat(filename, &statbuf) != 0) {
			create_path(udev, filename);
			udev_selinux_setfscreatecon(udev, filename, S_IFDIR|0755);
			mkdir(filename, 0755);
			udev_selinux_resetfscreatecon(udev);
		}
		udev_list_init(&sort_list);
		add_matching_files(udev, &sort_list, filename, ".rules");

		/* read default rules */
		add_matching_files(udev, &sort_list, UDEV_PREFIX "/lib/udev/rules.d", ".rules");

		/* sort all rules files by basename into list of files */
		udev_list_entry_foreach_safe(sort_loop, sort_tmp, udev_list_get_entry(&sort_list)) {
			const char *sort_name = udev_list_entry_get_name(sort_loop);
			const char *sort_base = strrchr(sort_name, '/');

			if (sort_base == NULL)
				continue;

			udev_list_entry_foreach_safe(file_loop, file_tmp, udev_list_get_entry(&file_list)) {
				const char *file_name = udev_list_entry_get_name(file_loop);
				const char *file_base = strrchr(file_name, '/');

				if (file_base == NULL)
					continue;
				if (strcmp(file_base, sort_base) == 0) {
					info(udev, "rule file basename '%s' already added, ignoring '%s'\n",
					     file_name, sort_name);
					udev_list_entry_remove(sort_loop);
					sort_loop = NULL;
					break;
				}
				if (strcmp(file_base, sort_base) > 0)
					break;
			}
			if (sort_loop != NULL)
				udev_list_entry_move_before(sort_loop, file_loop);
		}
	}

	/* parse list of files */
	udev_list_entry_foreach_safe(file_loop, file_tmp, udev_list_get_entry(&file_list)) {
		const char *file_name = udev_list_entry_get_name(file_loop);

		if (stat(file_name, &statbuf) == 0 && statbuf.st_size > 0)
			parse_file(rules, file_name);
		else
			info(udev, "can not read '%s'\n", file_name);
		udev_list_entry_remove(file_loop);
	}
	return rules;
}

void udev_rules_unref(struct udev_rules *rules)
{
	if (rules == NULL)
		return;
	if (rules->buf) {
		free(rules->buf);
		rules->buf = NULL;
	}
	free(rules);
}
