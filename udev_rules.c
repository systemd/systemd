/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fnmatch.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "udev.h"
#include "udev_rules.h"


/* extract possible {attr} and move str behind it */
static char *get_format_attribute(char **str)
{
	char *pos;
	char *attr = NULL;

	if (*str[0] == '{') {
		pos = strchr(*str, '}');
		if (pos == NULL) {
			err("missing closing brace for format");
			return NULL;
		}
		pos[0] = '\0';
		attr = *str+1;
		*str = pos+1;
		dbg("attribute='%s', str='%s'", attr, *str);
	}
	return attr;
}

/* extract possible format length and move str behind it*/
static int get_format_len(char **str)
{
	int num;
	char *tail;

	if (isdigit(*str[0])) {
		num = (int) strtoul(*str, &tail, 10);
		if (num > 0) {
			*str = tail;
			dbg("format length=%i", num);
			return num;
		} else {
			err("format parsing error '%s'", *str);
		}
	}
	return -1;
}

static int get_key(char **line, char **key, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (!linepos)
		return -1;

	if (strchr(linepos, '\\')) {
		dbg("escaped characters are not supported, skip");
		return -1;
	}

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
	if (linepos[0] == '"') {
		linepos++;
		temp = strchr(linepos, '"');
		if (!temp) {
			dbg("missing closing quote");
			return -1;
		}
		dbg("value is quoted");
		temp[0] = '\0';
	} else if (linepos[0] == '\'') {
		linepos++;
		temp = strchr(linepos, '\'');
		if (!temp) {
			dbg("missing closing quote");
			return -1;
		}
		dbg("value is quoted");
		temp[0] = '\0';
	} else if (linepos[0] == '\0') {
		dbg("value is empty");
	} else {
		temp = linepos;
		while (temp[0] && !isspace(temp[0]))
			temp++;
		temp[0] = '\0';
	}
	*value = linepos;

	return 0;
}

static int import_keys_into_env(struct udevice *udev, const char *buf, size_t bufsize)
{
	char line[LINE_SIZE];
	const char *bufline;
	char *linepos;
	char *variable;
	char *value;
	size_t cur;
	size_t count;
	int lineno;

	/* loop through the whole buffer */
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
		if (get_key(&linepos, &variable, &value) == 0) {
			dbg("import '%s=%s'", variable, value);
			name_list_key_add(&udev->env_list, variable, value);
			setenv(variable, value, 1);
		}
	}

	return 0;
}

static int import_file_into_env(struct udevice *udev, const char *filename)
{
	char *buf;
	size_t bufsize;

	if (file_map(filename, &buf, &bufsize) != 0) {
		err("can't open '%s': %s", filename, strerror(errno));
		return -1;
	}
	import_keys_into_env(udev, buf, bufsize);
	file_unmap(buf, bufsize);

	return 0;
}

static int import_program_into_env(struct udevice *udev, const char *program)
{
	char result[1024];
	size_t reslen;

	if (run_program(program, udev->dev->subsystem, result, sizeof(result), &reslen, (udev_log_priority >= LOG_INFO)) != 0)
		return -1;
	return import_keys_into_env(udev, result, reslen);
}

static int import_parent_into_env(struct udevice *udev, const char *filter)
{
	struct sysfs_device *dev_parent;
	int rc = -1;

	dev_parent = sysfs_device_get_parent(udev->dev);
	if (dev_parent != NULL) {
		struct udevice *udev_parent;
		struct name_entry *name_loop;

		dbg("found parent '%s', get the node name", dev_parent->devpath);
		udev_parent = udev_device_init();
		if (udev_parent == NULL)
			return -1;
		/* import the udev_db of the parent */
		if (udev_db_get_device(udev_parent, dev_parent->devpath) == 0) {
			dbg("import stored parent env '%s'", udev_parent->name);
			list_for_each_entry(name_loop, &udev_parent->env_list, node) {
				char name[NAME_SIZE];
				char *pos;

				strlcpy(name, name_loop->name, sizeof(name));
				pos = strchr(name, '=');
				if (pos) {
					pos[0] = '\0';
					pos++;
					if (fnmatch(filter, name, 0) == 0) {
						dbg("import key '%s'", name_loop->name);
						name_list_add(&udev->env_list, name_loop->name, 0);
						setenv(name, pos, 1);
					} else
						dbg("skip key '%s'", name_loop->name);
				}
			}
			rc = 0;
		} else
			dbg("parent not found in database");
		udev_device_cleanup(udev_parent);
	}

	return rc;
}

#define WAIT_LOOP_PER_SECOND		50
static int wait_for_sysfs(struct udevice *udev, const char *file, int timeout)
{
	char devicepath[PATH_SIZE];
	char filepath[PATH_SIZE];
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	strlcpy(devicepath, sysfs_path, sizeof(devicepath));
	strlcat(devicepath, udev->dev->devpath, sizeof(devicepath));
	strlcpy(filepath, devicepath, sizeof(filepath));
	strlcat(filepath, "/", sizeof(filepath));
	strlcat(filepath, file, sizeof(filepath));

	dbg("will wait %i sec for '%s'", timeout, filepath);
	while (--loop) {
		/* lookup file */
		if (stat(filepath, &stats) == 0) {
			info("file '%s' appeared after %i loops", filepath, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		/* make sure the device does not have disappeared in the meantime */
		if (stat(devicepath, &stats) != 0) {
			info("device disappeared while waiting for '%s'", filepath);
			return -2;
		}
		info("wait for '%s' for %i mseconds", filepath, 1000 / WAIT_LOOP_PER_SECOND);
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	err("waiting for '%s' failed", filepath);
	return -1;
}

void udev_rules_apply_format(struct udevice *udev, char *string, size_t maxsize)
{
	char temp[PATH_SIZE];
	char temp2[PATH_SIZE];
	char *head, *tail, *pos, *cpos, *attr, *rest;
	int len;
	int i;
	int count;
	enum subst_type {
		SUBST_UNKNOWN,
		SUBST_DEVPATH,
		SUBST_KERNEL,
		SUBST_KERNEL_NUMBER,
		SUBST_ID,
		SUBST_MAJOR,
		SUBST_MINOR,
		SUBST_RESULT,
		SUBST_ATTR,
		SUBST_PARENT,
		SUBST_TEMP_NODE,
		SUBST_ROOT,
		SUBST_ENV,
	};
	static const struct subst_map {
		char *name;
		char fmt;
		enum subst_type type;
	} map[] = {
		{ .name = "devpath",	.fmt = 'p',	.type = SUBST_DEVPATH },
		{ .name = "number",	.fmt = 'n',	.type = SUBST_KERNEL_NUMBER },
		{ .name = "kernel",	.fmt = 'k',	.type = SUBST_KERNEL },
		{ .name = "id",		.fmt = 'b',	.type = SUBST_ID },
		{ .name = "major",	.fmt = 'M',	.type = SUBST_MAJOR },
		{ .name = "minor",	.fmt = 'm',	.type = SUBST_MINOR },
		{ .name = "result",	.fmt = 'c',	.type = SUBST_RESULT },
		{ .name = "attr",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "sysfs",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "parent",	.fmt = 'P',	.type = SUBST_PARENT },
		{ .name = "tempnode",	.fmt = 'N',	.type = SUBST_TEMP_NODE },
		{ .name = "root",	.fmt = 'r',	.type = SUBST_ROOT },
		{ .name = "env",	.fmt = 'E',	.type = SUBST_ENV },
		{ NULL, '\0', 0 }
	};
	enum subst_type type;
	const struct subst_map *subst;

	head = string;
	while (1) {
		len = -1;
		while (head[0] != '\0') {
			if (head[0] == '$') {
				/* substitute named variable */
				if (head[1] == '\0')
					break;
				if (head[1] == '$') {
					strlcpy(temp, head+2, sizeof(temp));
					strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				for (subst = map; subst->name; subst++) {
					if (strncasecmp(&head[1], subst->name, strlen(subst->name)) == 0) {
						type = subst->type;
						tail = head + strlen(subst->name)+1;
						dbg("will substitute format name '%s'", subst->name);
						goto found;
					}
				}
				head[0] = '$';
				err("unknown format variable '%s'", head);
			} else if (head[0] == '%') {
				/* substitute format char */
				if (head[1] == '\0')
					break;
				if (head[1] == '%') {
					strlcpy(temp, head+2, sizeof(temp));
					strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				tail = head+1;
				len = get_format_len(&tail);
				for (subst = map; subst->name; subst++) {
					if (tail[0] == subst->fmt) {
						type = subst->type;
						tail++;
						dbg("will substitute format char '%c'", subst->fmt);
						goto found;
					}
				}
				head[0] = '%';
				err("unknown format char '%c'", tail[0]);
			}
			head++;
		}
		break;
found:
		attr = get_format_attribute(&tail);
		strlcpy(temp, tail, sizeof(temp));
		dbg("format=%i, string='%s', tail='%s'", type ,string, tail);

		switch (type) {
		case SUBST_DEVPATH:
			strlcat(string, udev->dev->devpath, maxsize);
			dbg("substitute devpath '%s'", udev->dev->devpath);
			break;
		case SUBST_KERNEL:
			strlcat(string, udev->dev->kernel, maxsize);
			dbg("substitute kernel name '%s'", udev->dev->kernel);
			break;
		case SUBST_KERNEL_NUMBER:
			strlcat(string, udev->dev->kernel_number, maxsize);
			dbg("substitute kernel number '%s'", udev->dev->kernel_number);
			break;
		case SUBST_ID:
			if (udev->dev_parent != NULL) {
				strlcat(string, udev->dev_parent->kernel, maxsize);
				dbg("substitute id '%s'", udev->dev_parent->kernel);
			}
			break;
		case SUBST_MAJOR:
			sprintf(temp2, "%d", major(udev->devt));
			strlcat(string, temp2, maxsize);
			dbg("substitute major number '%s'", temp2);
			break;
		case SUBST_MINOR:
			sprintf(temp2, "%d", minor(udev->devt));
			strlcat(string, temp2, maxsize);
			dbg("substitute minor number '%s'", temp2);
			break;
		case SUBST_RESULT:
			if (udev->program_result[0] == '\0')
				break;
			/* get part part of the result string */
			i = 0;
			if (attr != NULL)
				i = strtoul(attr, &rest, 10);
			if (i > 0) {
				dbg("request part #%d of result string", i);
				cpos = udev->program_result;
				while (--i) {
					while (cpos[0] != '\0' && !isspace(cpos[0]))
						cpos++;
					while (isspace(cpos[0]))
						cpos++;
				}
				if (i > 0) {
					err("requested part of result string not found");
					break;
				}
				strlcpy(temp2, cpos, sizeof(temp2));
				/* %{2+}c copies the whole string from the second part on */
				if (rest[0] != '+') {
					cpos = strchr(temp2, ' ');
					if (cpos)
						cpos[0] = '\0';
				}
				strlcat(string, temp2, maxsize);
				dbg("substitute part of result string '%s'", temp2);
			} else {
				strlcat(string, udev->program_result, maxsize);
				dbg("substitute result string '%s'", udev->program_result);
			}
			break;
		case SUBST_ATTR:
			if (attr == NULL)
				err("missing file parameter for attr");
			else {
				const char *value = NULL;
				size_t size;

				/* first try the current device, other matches may have selected */
				if (udev->dev_parent != NULL && udev->dev_parent != udev->dev)
					value = sysfs_attr_get_value(udev->dev_parent->devpath, attr);

				/* look at all devices along the chain of parents */
				if (value == NULL) {
					struct sysfs_device *dev_parent = udev->dev;

					do {
						dbg("looking at '%s'", dev_parent->devpath);
						value = sysfs_attr_get_value(dev_parent->devpath, attr);
						if (value != NULL) {
							strlcpy(temp2, value, sizeof(temp2));
							break;
						}
						dev_parent = sysfs_device_get_parent(dev_parent);
					} while (dev_parent != NULL);
				}

				if (value == NULL)
					break;

				/* strip trailing whitespace and replace untrusted characters of sysfs value */
				size = strlcpy(temp2, value, sizeof(temp2));
				if (size >= sizeof(temp2))
					size = sizeof(temp2)-1;
				while (size > 0 && isspace(temp2[size-1]))
					temp2[--size] = '\0';
				count = replace_untrusted_chars(temp2);
				if (count > 0)
					info("%i untrusted character(s) replaced" , count);
				strlcat(string, temp2, maxsize);
				dbg("substitute sysfs value '%s'", temp2);
			}
			break;
		case SUBST_PARENT:
			{
				struct sysfs_device *dev_parent;

				dev_parent = sysfs_device_get_parent(udev->dev);
				if (dev_parent != NULL) {
					struct udevice *udev_parent;

					dbg("found parent '%s', get the node name", dev_parent->devpath);
					udev_parent = udev_device_init();
					if (udev_parent != NULL) {
						/* lookup the name in the udev_db with the DEVPATH of the parent */
						if (udev_db_get_device(udev_parent, dev_parent->devpath) == 0) {
							strlcat(string, udev_parent->name, maxsize);
							dbg("substitute parent node name'%s'", udev_parent->name);
						} else
							dbg("parent not found in database");
						udev_device_cleanup(udev_parent);
					}
				}
			}
			break;
		case SUBST_TEMP_NODE:
			if (udev->tmp_node[0] == '\0') {
				dbg("create temporary device node for callout");
				snprintf(udev->tmp_node, sizeof(udev->tmp_node), "%s/.tmp-%u-%u",
					 udev_root, major(udev->devt), minor(udev->devt));
				udev->tmp_node[sizeof(udev->tmp_node)-1] = '\0';
				udev_node_mknod(udev, udev->tmp_node, udev->devt, 0600, 0, 0);
			}
			strlcat(string, udev->tmp_node, maxsize);
			dbg("substitute temporary device node name '%s'", udev->tmp_node);
			break;
		case SUBST_ROOT:
			strlcat(string, udev_root, maxsize);
			dbg("substitute udev_root '%s'", udev_root);
			break;
		case SUBST_ENV:
			if (attr == NULL) {
				dbg("missing attribute");
				break;
			}
			pos = getenv(attr);
			if (pos == NULL) {
				dbg("env '%s' not available", attr);
				break;
			}
			dbg("substitute env '%s=%s'", attr, pos);
			strlcat(string, pos, maxsize);
			break;
		default:
			err("unknown substitution type=%i", type);
			break;
		}
		/* possibly truncate to format-char specified length */
		if (len >= 0 && len < (int)strlen(head)) {
			head[len] = '\0';
			dbg("truncate to %i chars, subtitution string becomes '%s'", len, head);
		}
		strlcat(string, temp, maxsize);
	}
}

static char *key_val(struct udev_rule *rule, struct key *key)
{
	return rule->buf + key->val_off;
}

static char *key_pair_name(struct udev_rule *rule, struct key_pair *pair)
{
	return rule->buf + pair->key_name_off;
}

static int match_key(const char *key_name, struct udev_rule *rule, struct key *key, const char *val)
{
	int match;
	char value[PATH_SIZE];
	char *key_value;
	char *pos;

	if (key->operation != KEY_OP_MATCH &&
	    key->operation != KEY_OP_NOMATCH)
		return 0;

	strlcpy(value, rule->buf + key->val_off, sizeof(value));
	key_value = value;

	dbg("key %s value='%s'", key_name, key_value);
	while (key_value) {
		pos = strchr(key_value, '|');
		if (pos) {
			pos[0] = '\0';
			pos++;
		}
		dbg("match %s '%s' <-> '%s'", key_name, key_value, val);
		match = (fnmatch(key_value, val, 0) == 0);
		if (match && (key->operation != KEY_OP_NOMATCH)) {
			dbg("%s is true (matching value)", key_name);
			return 0;
		}
		if (!match && (key->operation == KEY_OP_NOMATCH)) {
			dbg("%s is true (non-matching value)", key_name);
			return 0;
		}
		key_value = pos;
	}
	dbg("%s is false", key_name);
	return -1;
}

/* match a single rule against a given device and possibly its parent devices */
static int match_rule(struct udevice *udev, struct udev_rule *rule)
{
	int i;

	if (match_key("ACTION", rule, &rule->action, udev->action))
		goto nomatch;

	if (match_key("KERNEL", rule, &rule->kernel, udev->dev->kernel))
		goto nomatch;

	if (match_key("SUBSYSTEM", rule, &rule->subsystem, udev->dev->subsystem))
		goto nomatch;

	if (match_key("DEVPATH", rule, &rule->devpath, udev->dev->devpath))
		goto nomatch;

	if (match_key("DRIVER", rule, &rule->driver, udev->dev->driver))
		goto nomatch;

	/* match NAME against a value assigned by an earlier rule */
	if (match_key("NAME", rule, &rule->name, udev->name))
		goto nomatch;

	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		/* we only check for matches, assignments will be handled later */
		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			const char *key_name = key_pair_name(rule, pair);
			const char *value = getenv(key_name);

			if (!value) {
				dbg("ENV{'%s'} is not set, treat as empty", key_name);
				value = "";
			}
			if (match_key("ENV", rule, &pair->key, value))
				goto nomatch;
		}
	}

	if (rule->wait_for_sysfs.operation != KEY_OP_UNSET) {
		int found;

		found = (wait_for_sysfs(udev, key_val(rule, &rule->wait_for_sysfs), 3) == 0);
		if (!found && (rule->wait_for_sysfs.operation != KEY_OP_NOMATCH))
			goto nomatch;
	}

	/* check for matching sysfs attribute pairs */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			const char *key_name = key_pair_name(rule, pair);
			const char *key_value = key_val(rule, &pair->key);
			const char *value;
			char val[VALUE_SIZE];
			size_t len;

			value = sysfs_attr_get_value(udev->dev->devpath, key_name);
			if (value == NULL)
				goto nomatch;
			strlcpy(val, value, sizeof(val));

			/* strip trailing whitespace of value, if not asked to match for it */
			len = strlen(key_value);
			if (len > 0 && !isspace(key_value[len-1])) {
				len = strlen(val);
				while (len > 0 && isspace(val[len-1]))
					val[--len] = '\0';
				dbg("removed %zi trailing whitespace chars from '%s'", strlen(val)-len, val);
			}

			if (match_key("ATTR", rule, &pair->key, val))
				goto nomatch;
		}
	}

	/* walk up the chain of parent devices and find a match */
	udev->dev_parent = udev->dev;
	while (1) {
		/* check for matching kernel device name */
		if (match_key("KERNELS", rule, &rule->kernels, udev->dev_parent->kernel))
			goto try_parent;

		/* check for matching subsystem value */
		if (match_key("SUBSYSTEMS", rule, &rule->subsystems, udev->dev_parent->subsystem))
			goto try_parent;

		/* check for matching driver */
		if (match_key("DRIVERS", rule, &rule->drivers, udev->dev_parent->driver))
			goto try_parent;

		/* check for matching sysfs attribute pairs */
		for (i = 0; i < rule->attrs.count; i++) {
			struct key_pair *pair = &rule->attrs.keys[i];

			if (pair->key.operation == KEY_OP_MATCH ||
			    pair->key.operation == KEY_OP_NOMATCH) {
				const char *key_name = key_pair_name(rule, pair);
				const char *key_value = key_val(rule, &pair->key);
				const char *value;
				char val[VALUE_SIZE];
				size_t len;

				value = sysfs_attr_get_value(udev->dev_parent->devpath, key_name);
				if (value == NULL)
					value = sysfs_attr_get_value(udev->dev->devpath, key_name);
				if (value == NULL)
					goto try_parent;
				strlcpy(val, value, sizeof(val));

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(key_value);
				if (len > 0 && !isspace(key_value[len-1])) {
					len = strlen(val);
					while (len > 0 && isspace(val[len-1]))
						val[--len] = '\0';
					dbg("removed %zi trailing whitespace chars from '%s'", strlen(val)-len, val);
				}

				if (match_key("ATTRS", rule, &pair->key, val))
					goto try_parent;
			}
		}

		/* found matching device  */
		break;
try_parent:
		/* move to parent device */
		dbg("try parent sysfs device");
		udev->dev_parent = sysfs_device_get_parent(udev->dev_parent);
		if (udev->dev_parent == NULL)
			goto nomatch;
		dbg("looking at dev_parent->devpath='%s'", udev->dev_parent->devpath);
		dbg("looking at dev_parent->kernel='%s'", udev->dev_parent->kernel);
	}

	/* execute external program */
	if (rule->program.operation != KEY_OP_UNSET) {
		char program[PATH_SIZE];
		char result[PATH_SIZE];

		strlcpy(program, key_val(rule, &rule->program), sizeof(program));
		udev_rules_apply_format(udev, program, sizeof(program));
		if (run_program(program, udev->dev->subsystem, result, sizeof(result), NULL, (udev_log_priority >= LOG_INFO)) != 0) {
			dbg("PROGRAM is false");
			udev->program_result[0] = '\0';
			if (rule->program.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else {
			int count;

			dbg("PROGRAM matches");
			remove_trailing_chars(result, '\n');
			count = replace_untrusted_chars(result);
			if (count)
				info("%i untrusted character(s) replaced" , count);
			dbg("result is '%s'", result);
			strlcpy(udev->program_result, result, sizeof(udev->program_result));
			dbg("PROGRAM returned successful");
			if (rule->program.operation == KEY_OP_NOMATCH)
				goto nomatch;
		}
		dbg("PROGRAM key is true");
	}

	/* check for matching result of external program */
	if (match_key("RESULT", rule, &rule->result, udev->program_result))
		goto nomatch;

	/* import variables returned from program or or file into environment */
	if (rule->import.operation != KEY_OP_UNSET) {
		char import[PATH_SIZE];
		int rc = -1;

		strlcpy(import, key_val(rule, &rule->import), sizeof(import));
		udev_rules_apply_format(udev, import, sizeof(import));
		dbg("check for IMPORT import='%s'", import);
		if (rule->import_type == IMPORT_PROGRAM) {
			rc = import_program_into_env(udev, import);
		} else if (rule->import_type == IMPORT_FILE) {
			dbg("import file import='%s'", import);
			rc = import_file_into_env(udev, import);
		} else if (rule->import_type == IMPORT_PARENT) {
			dbg("import parent import='%s'", import);
			rc = import_parent_into_env(udev, import);
		}
		if (rc != 0) {
			dbg("IMPORT failed");
			if (rule->import.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else
			dbg("IMPORT '%s' imported", key_val(rule, &rule->import));
		dbg("IMPORT key is true");
	}

	/* rule matches, if we have ENV assignments export it */
	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			char temp_value[NAME_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *value = key_val(rule, &pair->key);
			char *key_value;

			/* make sure we don't write to the same string we possibly read from */
			strlcpy(temp_value, value, sizeof(temp_value));
			udev_rules_apply_format(udev, temp_value, NAME_SIZE);

			key_value = name_list_key_add(&udev->env_list, key_name, temp_value);
			if (key_value == NULL)
				break;

			putenv(key_value);
			dbg("export ENV '%s'", key_value);
		}
	}

	/* if we have ATTR assignements write value to sysfs file */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			char attr[PATH_SIZE];
			char value[NAME_SIZE];
			FILE *f;

			strlcpy(attr, sysfs_path, sizeof(attr));
			strlcat(attr, udev->dev->devpath, sizeof(attr));
			strlcat(attr, "/", sizeof(attr));
			strlcat(attr, key_name, sizeof(attr));
			strlcpy(value, key_val(rule, &pair->key), sizeof(value));
			udev_rules_apply_format(udev, value, sizeof(value));
			info("writing '%s' to sysfs file '%s'", value, attr);
			f = fopen(attr, "w");
			if (f != NULL) {
				if (fprintf(f, "%s", value) <= 0)
					err("error writing ATTR{%s}: %s", attr, strerror(errno));
				fclose(f);
			} else
				err("error opening ATTR{%s} for writing: %s", attr, strerror(errno));
		}
	}
	return 0;

nomatch:
	return -1;
}

int udev_rules_get_name(struct udev_rules *rules, struct udevice *udev)
{
	struct udev_rule *rule;
	int name_set = 0;

	dbg("udev->dev->devpath='%s'", udev->dev->devpath);
	dbg("udev->dev->kernel='%s'", udev->dev->kernel);

	/* look for a matching rule to apply */
	udev_rules_iter_init(rules);
	while (1) {
		rule = udev_rules_iter_next(rules);
		if (rule == NULL)
			break;

		if (name_set &&
		    (rule->name.operation == KEY_OP_ASSIGN ||
		     rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		     rule->name.operation == KEY_OP_ADD)) {
			dbg("node name already set, rule ignored");
			continue;
		}

		dbg("process rule");
		if (match_rule(udev, rule) == 0) {
			/* apply options */
			if (rule->ignore_device) {
				info("rule applied, '%s' is ignored", udev->dev->kernel);
				udev->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev->ignore_remove = 1;
				dbg("remove event should be ignored");
			}
			/* apply all_partitions option only at a main block device */
			if (rule->partitions &&
			    strcmp(udev->dev->subsystem, "block") == 0 && udev->dev->kernel_number[0] == '\0') {
				udev->partitions = rule->partitions;
				dbg("creation of partition nodes requested");
			}

			/* apply permissions */
			if (!udev->mode_final && rule->mode != 0000) {
				if (rule->mode_operation == KEY_OP_ASSIGN_FINAL)
					udev->mode_final = 1;
				udev->mode = rule->mode;
				dbg("applied mode=%#o to '%s'", rule->mode, udev->dev->kernel);
			}
			if (!udev->owner_final && rule->owner.operation != KEY_OP_UNSET) {
				if (rule->owner.operation == KEY_OP_ASSIGN_FINAL)
					udev->owner_final = 1;
				strlcpy(udev->owner, key_val(rule, &rule->owner), sizeof(udev->owner));
				udev_rules_apply_format(udev, udev->owner, sizeof(udev->owner));
				dbg("applied owner='%s' to '%s'", udev->owner, udev->dev->kernel);
			}
			if (!udev->group_final && rule->group.operation != KEY_OP_UNSET) {
				if (rule->group.operation == KEY_OP_ASSIGN_FINAL)
					udev->group_final = 1;
				strlcpy(udev->group, key_val(rule, &rule->group), sizeof(udev->group));
				udev_rules_apply_format(udev, udev->group, sizeof(udev->group));
				dbg("applied group='%s' to '%s'", udev->group, udev->dev->kernel);
			}

			/* collect symlinks */
			if (!udev->symlink_final && rule->symlink.operation != KEY_OP_UNSET) {
				char temp[PATH_SIZE];
				char *pos, *next;
				int count;

				if (rule->symlink.operation == KEY_OP_ASSIGN_FINAL)
					udev->symlink_final = 1;
				if (rule->symlink.operation == KEY_OP_ASSIGN || rule->symlink.operation == KEY_OP_ASSIGN_FINAL) {
					info("reset symlink list");
					name_list_cleanup(&udev->symlink_list);
				}
				strlcpy(temp, key_val(rule, &rule->symlink), sizeof(temp));
				udev_rules_apply_format(udev, temp, sizeof(temp));
				count = replace_untrusted_chars(temp);
				if (count)
					info("%i untrusted character(s) replaced" , count);
				dbg("rule applied, added symlink(s) '%s'", temp);

				/* add multiple symlinks separated by spaces */
				pos = temp;
				while (isspace(pos[0]))
					pos++;
				next = strchr(pos, ' ');
				while (next) {
					next[0] = '\0';
					info("add symlink '%s'", pos);
					name_list_add(&udev->symlink_list, pos, 0);
					while (isspace(next[1]))
						next++;
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				if (pos[0] != '\0') {
					info("add symlink '%s'", pos);
					name_list_add(&udev->symlink_list, pos, 0);
				}
			}

			/* set name, later rules with name set will be ignored */
			if (rule->name.operation == KEY_OP_ASSIGN ||
			    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
			    rule->name.operation == KEY_OP_ADD) {
				int count;

				name_set = 1;
				strlcpy(udev->name, key_val(rule, &rule->name), sizeof(udev->name));
				udev_rules_apply_format(udev, udev->name, sizeof(udev->name));
				count = replace_untrusted_chars(udev->name);
				if (count)
					info("%i untrusted character(s) replaced", count);

				info("rule applied, '%s' becomes '%s'", udev->dev->kernel, udev->name);
				if (strcmp(udev->dev->subsystem, "net") != 0)
					dbg("name, '%s' is going to have owner='%s', group='%s', mode=%#o partitions=%i",
					    udev->name, udev->owner, udev->group, udev->mode, udev->partitions);
			}

			if (!udev->run_final && rule->run.operation != KEY_OP_UNSET) {
				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					udev->run_final = 1;
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info("reset run list");
					name_list_cleanup(&udev->run_list);
				}
				dbg("add run '%s'", key_val(rule, &rule->run));
				name_list_add(&udev->run_list, key_val(rule, &rule->run), 0);
			}

			if (rule->last_rule) {
				dbg("last rule to be applied");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg("moving forward to label '%s'", key_val(rule, &rule->goto_label));
				udev_rules_iter_label(rules, key_val(rule, &rule->goto_label));
			}
		}
	}

	if (!name_set) {
		strlcpy(udev->name, udev->dev->kernel, sizeof(udev->name));
		info("no node name set, will use kernel name '%s'", udev->name);
	}

	if (udev->tmp_node[0] != '\0') {
		dbg("removing temporary device node");
		unlink_secure(udev->tmp_node);
		udev->tmp_node[0] = '\0';
	}

	return 0;
}

int udev_rules_get_run(struct udev_rules *rules, struct udevice *udev)
{
	struct udev_rule *rule;

	dbg("udev->kernel='%s'", udev->dev->kernel);

	/* look for a matching rule to apply */
	udev_rules_iter_init(rules);
	while (1) {
		rule = udev_rules_iter_next(rules);
		if (rule == NULL)
			break;

		dbg("process rule");
		if (rule->name.operation != KEY_OP_UNSET || rule->symlink.operation != KEY_OP_UNSET ||
		    rule->mode_operation != KEY_OP_UNSET || rule->owner.operation != KEY_OP_UNSET || rule->group.operation != KEY_OP_UNSET) {
			dbg("skip rule that names a device");
			continue;
		}

		if (match_rule(udev, rule) == 0) {
			if (rule->ignore_device) {
				info("rule applied, '%s' is ignored", udev->dev->kernel);
				udev->ignore_device = 1;
				return 0;
			}

			if (!udev->run_final && rule->run.operation != KEY_OP_UNSET) {
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info("reset run list");
					name_list_cleanup(&udev->run_list);
				}
				dbg("add run '%s'", key_val(rule, &rule->run));
				name_list_add(&udev->run_list, key_val(rule, &rule->run), 0);
				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					break;
			}

			if (rule->last_rule) {
				dbg("last rule to be applied");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg("moving forward to label '%s'", key_val(rule, &rule->goto_label));
				udev_rules_iter_label(rules, key_val(rule, &rule->goto_label));
			}
		}
	}

	return 0;
}
