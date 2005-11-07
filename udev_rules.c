/*
 * udev_rules.c
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2005 Kay Sievers <kay.sievers@vrfy.org>
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
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "list.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_db.h"


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

	if (run_program(program, udev->subsystem, result, sizeof(result), &reslen, (udev_log_priority >= LOG_INFO)) != 0)
		return -1;
	return import_keys_into_env(udev, result, reslen);
}

static int import_parent_into_env(struct udevice *udev, struct sysfs_class_device *class_dev, const char *filter)
{
	struct sysfs_class_device *parent = sysfs_get_classdev_parent(class_dev);
	int rc = -1;

	if (parent != NULL) {
		struct udevice udev_parent;
		struct name_entry *name_loop;

		dbg("found parent '%s', get the node name", parent->path);
		udev_init_device(&udev_parent, NULL, NULL, NULL);
		/* import the udev_db of the parent */
		if (udev_db_get_device(&udev_parent, &parent->path[strlen(sysfs_path)]) == 0) {
			dbg("import stored parent env '%s'", udev_parent.name);
			list_for_each_entry(name_loop, &udev_parent.env_list, node) {
				char name[NAME_SIZE];
				char *pos;

				strlcpy(name, name_loop->name, sizeof(name));
				pos = strchr(name, '=');
				if (pos) {
					pos[0] = '\0';
					pos++;
					if (strcmp_pattern(filter, name) == 0) {
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
		udev_cleanup_device(&udev_parent);
	}

	return rc;
}

static int match_name_and_get_number(const char *base, const char *devname)
{
	size_t baselen;
	char *endptr;
	int num;

	baselen = strlen(base);
	if (strncmp(base, devname, baselen) != 0)
		return -1;
	if (devname[baselen] == '\0')
		return 0;
	if (!isdigit(devname[baselen]))
		return -1;
	num = strtoul(&devname[baselen], &endptr, 10);
	if (endptr[0] != '\0')
		return -1;
	return num;
}

/* finds the lowest positive device number such that <name>N isn't present in the udevdb
 * if <name> doesn't exist, 0 is returned, N otherwise */
static int find_free_number(const char *base, const char *devpath)
{
	char db_devpath[PATH_SIZE];
	char filename[PATH_SIZE];
	struct udevice udev_db;
	int num = 0;

	/* check if the device already owns a matching name */
	udev_init_device(&udev_db, NULL, NULL, NULL);
	if (udev_db_get_device(&udev_db, devpath) == 0) {
		struct name_entry *name_loop;
		int devnum;

		devnum = match_name_and_get_number(base, udev_db.name);
		if (devnum >= 0) {
			num = devnum;
			dbg("device '%s', already has the node '%s' with num %u, use it", devpath, base, num);
			goto out;
		}
		list_for_each_entry(name_loop, &udev_db.symlink_list, node) {
			devnum = match_name_and_get_number(base, name_loop->name);
			if (devnum >= 0) {
				num = devnum;
				dbg("device '%s', already has a symlink '%s' with num %u, use it", devpath, base, num);
				goto out;
			}
		}
	}

	/* just search the database again and again until a free name is found */
	strlcpy(filename, base, sizeof(filename));
	while (1) {
		dbg("look for existing node '%s'", filename);
		if (udev_db_lookup_name(filename, db_devpath, sizeof(db_devpath)) != 0) {
			dbg("free num=%d", num);
			break;
		}

		num++;
		if (num > 100000) {
			err("find_free_number aborted at num=%d", num);
			num = -1;
			break;
		}
		snprintf(filename, sizeof(filename), "%s%d", base, num);
		filename[sizeof(filename)-1] = '\0';
	}

out:
	udev_cleanup_device(&udev_db);
	return num;
}

static int find_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device,
				const char *name, char *value, size_t len)
{
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_attribute *tmpattr;

	dbg("look for device attribute '%s'", name);
	if (class_dev) {
		dbg("look for class attribute '%s/%s'", class_dev->path, name);
		tmpattr = sysfs_get_classdev_attr(class_dev, name);
		if (tmpattr)
			goto attr_found;
		class_dev_parent = sysfs_get_classdev_parent(class_dev);
		if (class_dev_parent) {
			tmpattr = sysfs_get_classdev_attr(class_dev_parent, name);
			if (tmpattr)
				goto attr_found;
		}
	}
	if (sysfs_device) {
		dbg("look for devices attribute '%s/%s'", sysfs_device->path, name);
		tmpattr = sysfs_get_device_attr(sysfs_device, name);
		if (tmpattr)
			goto attr_found;
	}
	return -1;

attr_found:
	strlcpy(value, tmpattr->value, len);
	remove_trailing_chars(value, '\n');

	dbg("found attribute '%s'", tmpattr->path);
	return 0;
}

#define WAIT_LOOP_PER_SECOND			20
static int wait_for_sysfs(struct udevice *udev, const char *file, int timeout)
{
	char filename[PATH_SIZE];
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	snprintf(filename, sizeof(filename), "%s%s/%s", sysfs_path, udev->devpath, file);
	filename[sizeof(filename)-1] = '\0';
	dbg("wait %i sec for '%s'", timeout, filename);

	while (--loop) {
		if (stat(filename, &stats) == 0) {
			info("file appeared after %i loops", (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	info("waiting for '%s' failed", filename);
	return -1;
}

static void apply_format(struct udevice *udev, char *string, size_t maxsize,
			 struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	char temp[PATH_SIZE];
	char temp2[PATH_SIZE];
	char *head, *tail, *pos, *cpos, *attr, *rest;
	int len;
	int i;
	int count;
	unsigned int next_free_number;
	struct sysfs_class_device *class_dev_parent;
	enum subst_type {
		SUBST_UNKNOWN,
		SUBST_DEVPATH,
		SUBST_ID,
		SUBST_KERNEL_NUMBER,
		SUBST_KERNEL_NAME,
		SUBST_MAJOR,
		SUBST_MINOR,
		SUBST_RESULT,
		SUBST_SYSFS,
		SUBST_ENUM,
		SUBST_PARENT,
		SUBST_TEMP_NODE,
		SUBST_ROOT,
		SUBST_MODALIAS,
		SUBST_ENV,
	};
	static const struct subst_map {
		char *name;
		char fmt;
		enum subst_type type;
	} map[] = {
		{ .name = "devpath",		.fmt = 'p',	.type = SUBST_DEVPATH },
		{ .name = "id",			.fmt = 'b',	.type = SUBST_ID },
		{ .name = "number",		.fmt = 'n',	.type = SUBST_KERNEL_NUMBER },
		{ .name = "kernel",		.fmt = 'k',	.type = SUBST_KERNEL_NAME },
		{ .name = "major",		.fmt = 'M',	.type = SUBST_MAJOR },
		{ .name = "minor",		.fmt = 'm',	.type = SUBST_MINOR },
		{ .name = "result",		.fmt = 'c',	.type = SUBST_RESULT },
		{ .name = "sysfs",		.fmt = 's',	.type = SUBST_SYSFS },
		{ .name = "enum",		.fmt = 'e',	.type = SUBST_ENUM },
		{ .name = "parent",		.fmt = 'P',	.type = SUBST_PARENT },
		{ .name = "tempnode",		.fmt = 'N',	.type = SUBST_TEMP_NODE },
		{ .name = "root",		.fmt = 'r',	.type = SUBST_ROOT },
		{ .name = "modalias",		.fmt = 'A',	.type = SUBST_MODALIAS },
		{ .name = "env",		.fmt = 'E',	.type = SUBST_ENV },
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
			}
			else if (head[0] == '%') {
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
			}
			head++;
		}
		break;
found:
		attr = get_format_attribute(&tail);
		strlcpy(temp, tail, sizeof(temp));
		dbg("format=%i, string='%s', tail='%s', class_dev=%p, sysfs_dev=%p",
		    type ,string, tail, class_dev, sysfs_device);

		switch (type) {
		case SUBST_DEVPATH:
			strlcat(string, udev->devpath, maxsize);
			dbg("substitute devpath '%s'", udev->devpath);
			break;
		case SUBST_ID:
			strlcat(string, udev->bus_id, maxsize);
			dbg("substitute bus_id '%s'", udev->bus_id);
			break;
		case SUBST_KERNEL_NAME:
			strlcat(string, udev->kernel_name, maxsize);
			dbg("substitute kernel name '%s'", udev->kernel_name);
			break;
		case SUBST_KERNEL_NUMBER:
			strlcat(string, udev->kernel_number, maxsize);
			dbg("substitute kernel number '%s'", udev->kernel_number);
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
		case SUBST_SYSFS:
			if (attr == NULL) {
				dbg("missing attribute");
				break;
			}
			if (find_sysfs_attribute(class_dev, sysfs_device, attr, temp2, sizeof(temp2)) != 0) {
				struct sysfs_device *parent_device;

				dbg("sysfs attribute '%s' not found, walk up the physical devices", attr);
				parent_device = sysfs_get_device_parent(sysfs_device);
				while (parent_device) {
					dbg("looking at '%s'", parent_device->path);
					if (find_sysfs_attribute(NULL, parent_device, attr, temp2, sizeof(temp2)) == 0)
						break;
					parent_device = sysfs_get_device_parent(parent_device);
				}
				if (!parent_device)
					break;
			}
			/* strip trailing whitespace of sysfs value */
			i = strlen(temp2);
			while (i > 0 && isspace(temp2[i-1]))
				temp2[--i] = '\0';
			count = replace_untrusted_chars(temp2);
			if (count)
				info("%i untrusted character(s) replaced" , count);
			strlcat(string, temp2, maxsize);
			dbg("substitute sysfs value '%s'", temp2);
			break;
		case SUBST_ENUM:
			next_free_number = find_free_number(string, udev->devpath);
			if (next_free_number > 0) {
				sprintf(temp2, "%d", next_free_number);
				strlcat(string, temp2, maxsize);
			}
			break;
		case SUBST_PARENT:
			if (!class_dev)
				break;
			class_dev_parent = sysfs_get_classdev_parent(class_dev);
			if (class_dev_parent != NULL) {
				struct udevice udev_parent;

				dbg("found parent '%s', get the node name", class_dev_parent->path);
				udev_init_device(&udev_parent, NULL, NULL, NULL);
				/* lookup the name in the udev_db with the DEVPATH of the parent */
				if (udev_db_get_device(&udev_parent, &class_dev_parent->path[strlen(sysfs_path)]) == 0) {
					strlcat(string, udev_parent.name, maxsize);
					dbg("substitute parent node name'%s'", udev_parent.name);
				} else
					dbg("parent not found in database");
				udev_cleanup_device(&udev_parent);
			}
			break;
		case SUBST_TEMP_NODE:
			if (udev->tmp_node[0] == '\0') {
				dbg("create temporary device node for callout");
				snprintf(udev->tmp_node, sizeof(udev->tmp_node), "%s/.tmp-%u-%u",
					 udev_root, major(udev->devt), minor(udev->devt));
				udev->tmp_node[sizeof(udev->tmp_node)-1] = '\0';
				udev_make_node(udev, udev->tmp_node, udev->devt, 0600, 0, 0);
			}
			strlcat(string, udev->tmp_node, maxsize);
			dbg("substitute temporary device node name '%s'", udev->tmp_node);
			break;
		case SUBST_ROOT:
			strlcat(string, udev_root, maxsize);
			dbg("substitute udev_root '%s'", udev_root);
			break;
		case SUBST_MODALIAS:
			if (find_sysfs_attribute(NULL, sysfs_device, "modalias", temp2, sizeof(temp2)) != 0)
				break;
			strlcat(string, temp2, maxsize);
			dbg("substitute MODALIAS '%s'", temp2);
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
		if (len != -1) {
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

	if (key->operation == KEY_OP_UNSET)
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
		match = (strcmp_pattern(key_value, val) == 0);
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
static int match_rule(struct udevice *udev, struct udev_rule *rule,
		      struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	struct sysfs_device *parent_device = sysfs_device;
	int i;

	if (match_key("ACTION", rule, &rule->action, udev->action))
		goto exit;

	if (match_key("KERNEL", rule, &rule->kernel_name, udev->kernel_name))
		goto exit;

	if (match_key("SUBSYSTEM", rule, &rule->subsystem, udev->subsystem))
		goto exit;

	if (match_key("DEVPATH", rule, &rule->devpath, udev->devpath))
		goto exit;

	if (rule->modalias.operation != KEY_OP_UNSET) {
		char value[NAME_SIZE];

		if (find_sysfs_attribute(NULL, sysfs_device, "modalias", value, sizeof(value)) != 0) {
			dbg("MODALIAS value not found");
			goto exit;
		}
		if (match_key("MODALIAS", rule, &rule->modalias, value))
			goto exit;
	}

	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		/* we only check for matches, assignments will be handled later */
		if (pair->key.operation != KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			const char *value = getenv(key_name);

			if (!value) {
				dbg("ENV{'%s'} is not set, treat as empty", key_name);
				value = "";
			}
			if (match_key("ENV", rule, &pair->key, value))
				goto exit;
		}
	}

	if (rule->wait_for_sysfs.operation != KEY_OP_UNSET) {
		int match;

		match = (wait_for_sysfs(udev, key_val(rule, &rule->wait_for_sysfs), 3) == 0);
		if (match && (rule->wait_for_sysfs.operation != KEY_OP_NOMATCH)) {
			dbg("WAIT_FOR_SYSFS is true (matching value)");
			return 0;
		}
		if (!match && (rule->wait_for_sysfs.operation == KEY_OP_NOMATCH)) {
			dbg("WAIT_FOR_SYSFS is true, (non matching value)");
			return 0;
		}
		dbg("WAIT_FOR_SYSFS is false");
		return -1;
	}

	/* walk up the chain of physical devices and find a match */
	while (1) {
		/* check for matching driver */
		if (rule->driver.operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			if (match_key("DRIVER", rule, &rule->driver, parent_device->driver_name))
				goto try_parent;
		}

		/* check for matching bus value */
		if (rule->bus.operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			if (match_key("BUS", rule, &rule->bus, parent_device->bus))
				goto try_parent;
		}

		/* check for matching bus id */
		if (rule->id.operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			if (match_key("ID", rule, &rule->id, parent_device->bus_id))
				goto try_parent;
		}

		/* check for matching sysfs pairs */
		if (rule->sysfs.count) {
			dbg("check %i SYSFS keys", rule->sysfs.count);
			for (i = 0; i < rule->sysfs.count; i++) {
				struct key_pair *pair = &rule->sysfs.keys[i];
				const char *key_name = key_pair_name(rule, pair);
				const char *key_value = key_val(rule, &pair->key);
				char value[VALUE_SIZE];
				size_t len;

				if (find_sysfs_attribute(class_dev, parent_device, key_name, value, sizeof(value)) != 0)
					goto try_parent;

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(key_value);
				if (len && !isspace(key_value[len-1])) {
					len = strlen(value);
					while (len > 0 && isspace(value[len-1]))
						value[--len] = '\0';
					dbg("removed %zi trailing whitespace chars from '%s'", strlen(value)-len, value);
				}

				if (match_key("SYSFS", rule, &pair->key, value))
					goto try_parent;
			}
			dbg("all %i SYSFS keys matched", rule->sysfs.count);
		}

		/* found matching physical device  */
		break;
try_parent:
		dbg("try parent sysfs device");
		parent_device = sysfs_get_device_parent(parent_device);
		if (parent_device == NULL)
			goto exit;
		dbg("look at sysfs_device->path='%s'", parent_device->path);
		dbg("look at sysfs_device->bus_id='%s'", parent_device->bus_id);
	}

	/* execute external program */
	if (rule->program.operation != KEY_OP_UNSET) {
		char program[PATH_SIZE];
		char result[PATH_SIZE];

		strlcpy(program, key_val(rule, &rule->program), sizeof(program));
		apply_format(udev, program, sizeof(program), class_dev, sysfs_device);
		if (run_program(program, udev->subsystem, result, sizeof(result), NULL, (udev_log_priority >= LOG_INFO)) != 0) {
			dbg("PROGRAM is false");
			udev->program_result[0] = '\0';
			if (rule->program.operation != KEY_OP_NOMATCH)
				goto exit;
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
				goto exit;
		}
		dbg("PROGRAM key is true");
	}

	/* check for matching result of external program */
	if (match_key("RESULT", rule, &rule->result, udev->program_result))
		goto exit;

	/* import variables returned from program or or file into environment */
	if (rule->import.operation != KEY_OP_UNSET) {
		char import[PATH_SIZE];
		int rc = -1;

		strlcpy(import, key_val(rule, &rule->import), sizeof(import));
		apply_format(udev, import, sizeof(import), class_dev, sysfs_device);
		dbg("check for IMPORT import='%s'", import);
		if (rule->import_type == IMPORT_PROGRAM) {
			rc = import_program_into_env(udev, import);
		} else if (rule->import_type == IMPORT_FILE) {
			dbg("import file import='%s'", import);
			rc = import_file_into_env(udev, import);
		} else if (rule->import_type == IMPORT_PARENT && class_dev) {
			dbg("import parent import='%s'", import);
			rc = import_parent_into_env(udev, class_dev, import);
		}
		if (rc) {
			dbg("IMPORT failed");
			if (rule->import.operation != KEY_OP_NOMATCH)
				goto exit;
		} else
			dbg("IMPORT '%s' imported", key_val(rule, &rule->import));
		dbg("IMPORT key is true");
	}

	/* rule matches, if we have ENV assignments export it */
	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			const char *value = key_val(rule, &pair->key);

			name_list_key_add(&udev->env_list, key_name, value);
			setenv(key_name, value, 1);
			dbg("export ENV '%s=%s'", key_name, value);
		}
	}

	return 0;

exit:
	return -1;
}

int udev_rules_get_name(struct udev_rules *rules, struct udevice *udev, struct sysfs_class_device *class_dev)
{
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_device *sysfs_device = NULL;
	struct udev_rule *rule;
	int name_set = 0;

	dbg("class_dev->name='%s'", class_dev->name);

	/* Figure out where the "device"-symlink is at.  For char devices this will
	 * always be in the class_dev->path.  On block devices, only the main block
	 * device will have the device symlink in it's path. All partition devices
	 * need to look at the symlink in its parent directory.
	 */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent != NULL) {
		dbg("given class device has a parent, use this instead");
		sysfs_device = sysfs_get_classdev_device(class_dev_parent);
	} else {
		sysfs_device = sysfs_get_classdev_device(class_dev);
	}

	if (sysfs_device) {
		dbg("found devices device: path='%s', bus_id='%s', bus='%s'",
		    sysfs_device->path, sysfs_device->bus_id, sysfs_device->bus);
		strlcpy(udev->bus_id, sysfs_device->bus_id, sizeof(udev->bus_id));
	}

	dbg("udev->kernel_name='%s'", udev->kernel_name);

	/* look for a matching rule to apply */
	udev_rules_iter_init(rules);
	while (1) {
		rule = udev_rules_iter_next(rules);
		if (rule == NULL)
			break;

		if (name_set && rule->name.operation != KEY_OP_UNSET) {
			dbg("node name already set, rule ignored");
			continue;
		}

		dbg("process rule");
		if (match_rule(udev, rule, class_dev, sysfs_device) == 0) {
			/* apply options */
			if (rule->ignore_device) {
				info("rule applied, '%s' is ignored", udev->kernel_name);
				udev->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev->ignore_remove = 1;
				dbg("remove event should be ignored");
			}
			/* apply all_partitions option only at a main block device */
			if (rule->partitions && udev->type == DEV_BLOCK && udev->kernel_number[0] == '\0') {
				udev->partitions = rule->partitions;
				dbg("creation of partition nodes requested");
			}

			/* apply permissions */
			if (!udev->mode_final && rule->mode != 0000) {
				if (rule->mode_operation == KEY_OP_ASSIGN_FINAL)
					udev->mode_final = 1;
				udev->mode = rule->mode;
				dbg("applied mode=%#o to '%s'", rule->mode, udev->kernel_name);
			}
			if (!udev->owner_final && rule->owner.operation != KEY_OP_UNSET) {
				if (rule->owner.operation == KEY_OP_ASSIGN_FINAL)
					udev->owner_final = 1;
				strlcpy(udev->owner, key_val(rule, &rule->owner), sizeof(udev->owner));
				apply_format(udev, udev->owner, sizeof(udev->owner), class_dev, sysfs_device);
				dbg("applied owner='%s' to '%s'", udev->owner, udev->kernel_name);
			}
			if (!udev->group_final && rule->group.operation != KEY_OP_UNSET) {
				if (rule->group.operation == KEY_OP_ASSIGN_FINAL)
					udev->group_final = 1;
				strlcpy(udev->group, key_val(rule, &rule->group), sizeof(udev->group));
				apply_format(udev, udev->group, sizeof(udev->group), class_dev, sysfs_device);
				dbg("applied group='%s' to '%s'", udev->group, udev->kernel_name);
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
				apply_format(udev, temp, sizeof(temp), class_dev, sysfs_device);
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
			if (rule->name.operation != KEY_OP_UNSET) {
				int count;
				name_set = 1;
				strlcpy(udev->name, key_val(rule, &rule->name), sizeof(udev->name));
				apply_format(udev, udev->name, sizeof(udev->name), class_dev, sysfs_device);
				count = replace_untrusted_chars(udev->name);
				if (count)
					info("%i untrusted character(s) replaced", count);

				info("rule applied, '%s' becomes '%s'", udev->kernel_name, udev->name);
				if (udev->type != DEV_NET)
					dbg("name, '%s' is going to have owner='%s', group='%s', mode=%#o partitions=%i",
					    udev->name, udev->owner, udev->group, udev->mode, udev->partitions);
			}

			if (!udev->run_final && rule->run.operation != KEY_OP_UNSET) {
				char program[PATH_SIZE];

				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					udev->run_final = 1;
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info("reset run list");
					name_list_cleanup(&udev->run_list);
				}
				strlcpy(program, key_val(rule, &rule->run), sizeof(program));
				apply_format(udev, program, sizeof(program), class_dev, sysfs_device);
				dbg("add run '%s'", program);
				name_list_add(&udev->run_list, program, 0);
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
		strlcpy(udev->name, udev->kernel_name, sizeof(udev->name));
		info("no node name set, will use kernel name '%s'", udev->name);
	}

	if (udev->tmp_node[0] != '\0') {
		dbg("removing temporary device node");
		unlink_secure(udev->tmp_node);
		udev->tmp_node[0] = '\0';
	}

	return 0;
}

int udev_rules_get_run(struct udev_rules *rules, struct udevice *udev,
		       struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_dev)
{
	struct udev_rule *rule;

	if (class_dev && !sysfs_dev)
		sysfs_dev = sysfs_get_classdev_device(class_dev);
	if (sysfs_dev) {
		dbg("found devices device: path='%s', bus_id='%s', bus='%s'",
		    sysfs_dev->path, sysfs_dev->bus_id, sysfs_dev->bus);
		strlcpy(udev->bus_id, sysfs_dev->bus_id, sizeof(udev->bus_id));
	}

	dbg("udev->kernel_name='%s'", udev->kernel_name);

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

		if (match_rule(udev, rule, class_dev, sysfs_dev) == 0) {
			if (rule->ignore_device) {
				info("rule applied, '%s' is ignored", udev->kernel_name);
				udev->ignore_device = 1;
				return 0;
			}

			if (!udev->run_final && rule->run.operation != KEY_OP_UNSET) {
				char program[PATH_SIZE];

				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info("reset run list");
					name_list_cleanup(&udev->run_list);
				}
				strlcpy(program, key_val(rule, &rule->run), sizeof(program));
				apply_format(udev, program, sizeof(program), class_dev, sysfs_dev);
				dbg("add run '%s'", program);
				name_list_add(&udev->run_list, program, 0);
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
