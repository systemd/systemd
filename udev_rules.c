/*
 * udev_rules.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
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
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
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

static struct sysfs_attribute *find_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device, char *attr);

/* compare string with pattern (supports * ? [0-9] [!A-Z]) */
static int strcmp_pattern(const char *p, const char *s)
{
	if (s[0] == '\0') {
		while (p[0] == '*')
			p++;
		return (p[0] != '\0');
	}
	switch (p[0]) {
	case '[':
		{
			int not = 0;
			p++;
			if (p[0] == '!') {
				not = 1;
				p++;
			}
			while ((p[0] != '\0') && (p[0] != ']')) {
				int match = 0;
				if (p[1] == '-') {
					if ((s[0] >= p[0]) && (s[0] <= p[2]))
						match = 1;
					p += 3;
				} else {
					match = (p[0] == s[0]);
					p++;
				}
				if (match ^ not) {
					while ((p[0] != '\0') && (p[0] != ']'))
						p++;
					if (p[0] == ']')
						return strcmp_pattern(p+1, s+1);
				}
			}
		}
		break;
	case '*':
		if (strcmp_pattern(p, s+1))
			return strcmp_pattern(p+1, s);
		return 0;
	case '\0':
		if (s[0] == '\0') {
			return 0;
		}
		break;
	default:
		if ((p[0] == s[0]) || (p[0] == '?'))
			return strcmp_pattern(p+1, s+1);
		break;
	}
	return 1;
}

/* extract possible {attr} and move str behind it */
static char *get_format_attribute(char **str)
{
	char *pos;
	char *attr = NULL;

	if (*str[0] == '{') {
		pos = strchr(*str, '}');
		if (pos == NULL) {
			dbg("missing closing brace for format");
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
			dbg("format parsing error '%s'", *str);
		}
	}
	return -1;
}

/** Finds the lowest positive N such that <name>N isn't present in 
 *  $(udevroot) either as a file or a symlink.
 *
 *  @param  name                Name to check for
 *  @return                     0 if <name> didn't exist and N otherwise.
 */
static int find_free_number(struct udevice *udev, const char *name)
{
	char devpath[PATH_SIZE];
	char filename[PATH_SIZE];
	int num = 0;

	strlcpy(filename, name, sizeof(filename));
	while (1) {
		dbg("look for existing node '%s'", filename);
		if (udev_db_search_name(devpath, sizeof(devpath), filename) != 0) {
			dbg("free num=%d", num);
			return num;
		}

		num++;
		if (num > 1000) {
			info("find_free_number gone crazy (num=%d), aborted", num);
			return -1;
		}
		snprintf(filename, sizeof(filename), "%s%d", name, num);
		filename[sizeof(filename)-1] = '\0';
	}
}

static void apply_format(struct udevice *udev, char *string, size_t maxsize,
			 struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	char temp[PATH_SIZE];
	char temp2[PATH_SIZE];
	char *tail, *pos, *cpos, *attr, *rest;
	int len;
	int i;
	char c;
	struct sysfs_attribute *tmpattr;
	unsigned int next_free_number;
	struct sysfs_class_device *class_dev_parent;

	pos = string;
	while (1) {
		pos = strchr(pos, '%');
		if (pos == NULL)
			break;

		pos[0] = '\0';
		tail = pos+1;
		len = get_format_len(&tail);
		c = tail[0];
		strlcpy(temp, tail+1, sizeof(temp));
		tail = temp;
		dbg("format=%c, string='%s', tail='%s'",c , string, tail);
		attr = get_format_attribute(&tail);

		switch (c) {
		case 'p':
			strlcat(string, udev->devpath, maxsize);
			dbg("substitute kernel name '%s'", udev->kernel_name);
			break;
		case 'b':
			strlcat(string, udev->bus_id, maxsize);
			dbg("substitute bus_id '%s'", udev->bus_id);
			break;
		case 'k':
			strlcat(string, udev->kernel_name, maxsize);
			dbg("substitute kernel name '%s'", udev->kernel_name);
			break;
		case 'n':
			strlcat(string, udev->kernel_number, maxsize);
			dbg("substitute kernel number '%s'", udev->kernel_number);
				break;
		case 'm':
			sprintf(temp2, "%d", minor(udev->devt));
			strlcat(string, temp2, maxsize);
			dbg("substitute minor number '%s'", temp2);
			break;
		case 'M':
			sprintf(temp2, "%d", major(udev->devt));
			strlcat(string, temp2, maxsize);
			dbg("substitute major number '%s'", temp2);
			break;
		case 'c':
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
					dbg("requested part of result string not found");
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
		case 's':
			if (!class_dev)
				break;
			if (attr == NULL) {
				dbg("missing attribute");
				break;
			}
			tmpattr = find_sysfs_attribute(class_dev, sysfs_device, attr);
			if (tmpattr == NULL) {
				dbg("sysfa attribute '%s' not found", attr);
				break;
			}
			/* strip trailing whitespace of matching value */
			if (isspace(tmpattr->value[strlen(tmpattr->value)-1])) {
				i = len = strlen(tmpattr->value);
				while (i > 0 &&  isspace(tmpattr->value[i-1]))
					i--;
				if (i < len) {
					tmpattr->value[i] = '\0';
					dbg("remove %i trailing whitespace chars from '%s'",
						 len - i, tmpattr->value);
				}
			}
			strlcat(string, tmpattr->value, maxsize);
			dbg("substitute sysfs value '%s'", tmpattr->value);
			break;
		case '%':
			strlcat(string, "%", maxsize);
			pos++;
			break;
		case 'e':
			next_free_number = find_free_number(udev, string);
			if (next_free_number > 0) {
				sprintf(temp2, "%d", next_free_number);
				strlcat(string, temp2, maxsize);
			}
			break;
		case 'P':
			if (!class_dev)
				break;
			class_dev_parent = sysfs_get_classdev_parent(class_dev);
			if (class_dev_parent != NULL) {
				struct udevice udev_parent;

				dbg("found parent '%s', get the node name", class_dev_parent->path);
				udev_init_device(&udev_parent, NULL, NULL);
				/* lookup the name in the udev_db with the DEVPATH of the parent */
				if (udev_db_get_device(&udev_parent, &class_dev_parent->path[strlen(sysfs_path)]) == 0) {
					strlcat(string, udev_parent.name, maxsize);
					dbg("substitute parent node name'%s'", udev_parent.name);
				} else
					dbg("parent not found in database");
				udev_cleanup_device(&udev_parent);
			}
			break;
		case 'N':
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
		case 'r':
			strlcat(string, udev_root, maxsize);
			dbg("substitute udev_root '%s'", udev_root);
			break;
		default:
			dbg("unknown substitution type '%%%c'", c);
			break;
		}
		/* truncate to specified length */
		if (len > 0)
			pos[len] = '\0';

		strlcat(string, tail, maxsize);
	}
}

static int execute_program(struct udevice *udev, const char *path, char *value, int len)
{
	int retval;
	int count;
	int status;
	int fds[2];
	pid_t pid;
	char *pos;
	char arg[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int i;

	strlcpy(arg, path, sizeof(arg));
	i = 0;
	if (strchr(path, ' ')) {
		pos = arg;
		while (pos != NULL) {
			if (pos[0] == '\'') {
				/* don't separate if in apostrophes */
				pos++;
				argv[i] = strsep(&pos, "\'");
				while (pos && pos[0] == ' ')
					pos++;
			} else {
				argv[i] = strsep(&pos, " ");
			}
			dbg("arg[%i] '%s'", i, argv[i]);
			i++;
		}
		argv[i] =  NULL;
		dbg("execute '%s' with parsed arguments", arg);
	} else {
		argv[0] = arg;
		argv[1] = udev->subsystem;
		argv[2] = NULL;
		dbg("execute '%s' with subsystem '%s' argument", arg, argv[1]);
	}

	retval = pipe(fds);
	if (retval != 0) {
		dbg("pipe failed");
		return -1;
	}

	pid = fork();
	switch(pid) {
	case 0:
		/* child */
		/* dup2 write side of pipe to STDOUT */
		dup2(fds[1], STDOUT_FILENO);
		retval = execv(arg, argv);

		info(FIELD_PROGRAM " execution of '%s' failed", path);
		exit(1);
	case -1:
		dbg("fork failed");
		return -1;
	default:
		/* parent reads from fds[0] */
		close(fds[1]);
		retval = 0;
		i = 0;
		while (1) {
			count = read(fds[0], value + i, len - i-1);
			if (count <= 0)
				break;

			i += count;
			if (i >= len-1) {
				dbg("result len %d too short", len);
				retval = -1;
				break;
			}
		}

		if (count < 0) {
			dbg("read failed with '%s'", strerror(errno));
			retval = -1;
		}

		if (i > 0 && value[i-1] == '\n')
			i--;
		value[i] = '\0';
		dbg("result is '%s'", value);

		close(fds[0]);
		waitpid(pid, &status, 0);

		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("exec program status 0x%x", status);
			retval = -1;
		}
	}
	return retval;
}

static struct sysfs_attribute *find_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device, char *attr)
{
	struct sysfs_attribute *tmpattr = NULL;
	char *c;

	dbg("look for device attribute '%s'", attr);
	/* try to find the attribute in the class device directory */
	tmpattr = sysfs_get_classdev_attr(class_dev, attr);
	if (tmpattr)
		goto attr_found;

	/* look in the class device directory if present */
	if (sysfs_device) {
		tmpattr = sysfs_get_device_attr(sysfs_device, attr);
		if (tmpattr)
			goto attr_found;
	}

	return NULL;

attr_found:
	c = strchr(tmpattr->value, '\n');
	if (c != NULL)
		c[0] = '\0';

	dbg("found attribute '%s'", tmpattr->path);
	return tmpattr;
}

static int compare_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device, struct sysfs_pair *pair)
{
	struct sysfs_attribute *tmpattr;
	int i;
	int len;

	if ((pair == NULL) || (pair->file[0] == '\0') || (pair->value == '\0'))
		return -ENODEV;

	tmpattr = find_sysfs_attribute(class_dev, sysfs_device, pair->file);
	if (tmpattr == NULL)
		return -ENODEV;

	/* strip trailing whitespace of value, if not asked to match for it */
	if (! isspace(pair->value[strlen(pair->value)-1])) {
		i = len = strlen(tmpattr->value);
		while (i > 0 &&  isspace(tmpattr->value[i-1]))
			i--;
		if (i < len) {
			tmpattr->value[i] = '\0';
			dbg("remove %i trailing whitespace chars from '%s'",
			    len - i, tmpattr->value);
		}
	}

	dbg("compare attribute '%s' value '%s' with '%s'",
		  pair->file, tmpattr->value, pair->value);
	if (strcmp_pattern(pair->value, tmpattr->value) != 0)
		return -ENODEV;

	dbg("found matching attribute '%s' with value '%s'",
	    pair->file, pair->value);
	return 0;
}

static int match_sysfs_pairs(struct udev_rule *rule, struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	struct sysfs_pair *pair;
	int i;

	for (i = 0; i < MAX_SYSFS_PAIRS; ++i) {
		pair = &rule->sysfs_pair[i];
		if ((pair->file[0] == '\0') || (pair->value[0] == '\0'))
			break;
		if (compare_sysfs_attribute(class_dev, sysfs_device, pair) != 0) {
			dbg("sysfs attribute doesn't match");
			return -ENODEV;
		}
	}

	return 0;
}

static int match_id(struct udev_rule *rule, struct sysfs_device *sysfs_device)
{
	char path[PATH_SIZE];
	char *temp;

	strlcpy(path, sysfs_device->path, sizeof(path));
	temp = strrchr(path, '/');
	temp++;
	dbg("search '%s' in '%s', path='%s'", rule->id, temp, path);
	if (strcmp_pattern(rule->id, temp) != 0)
		return -ENODEV;

	return 0;
}

static int match_rule(struct udevice *udev, struct udev_rule *rule,
		      struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	if (rule->kernel[0] != '\0') {
		dbg("check for " FIELD_KERNEL " rule->kernel='%s' class_dev->name='%s'",
		    rule->kernel, class_dev->name);
		if (strcmp_pattern(rule->kernel, class_dev->name) != 0) {
			dbg(FIELD_KERNEL " is not matching");
			goto exit;
		}
		dbg(FIELD_KERNEL " matches");
	}

	if (rule->subsystem[0] != '\0') {
		dbg("check for " FIELD_SUBSYSTEM " rule->subsystem='%s' class_dev->name='%s'",
		    rule->subsystem, class_dev->name);
		if (strcmp_pattern(rule->subsystem, udev->subsystem) != 0) {
			dbg(FIELD_SUBSYSTEM " is not matching");
			goto exit;
		}
		dbg(FIELD_SUBSYSTEM " matches");
	}

	/* walk up the chain of physical devices and find a match */
	while (1) {
		/* check for matching driver */
		if (rule->driver[0] != '\0') {
			if (sysfs_device == NULL) {
				dbg("device has no sysfs_device");
				goto try_parent;
			}
			dbg("check for " FIELD_DRIVER " rule->driver='%s' sysfs_device->driver_name='%s'",
			    rule->driver, sysfs_device->driver_name);
			if (strcmp_pattern(rule->driver, sysfs_device->driver_name) != 0) {
				dbg(FIELD_DRIVER " is not matching");
				goto try_parent;
			}
			dbg(FIELD_DRIVER " matches");
		}

		/* check for matching bus value */
		if (rule->bus[0] != '\0') {
			if (sysfs_device == NULL) {
				dbg("device has no sysfs_device");
				goto try_parent;
			}
			dbg("check for " FIELD_BUS " rule->bus='%s' sysfs_device->bus='%s'",
			    rule->bus, sysfs_device->bus);
			if (strcmp_pattern(rule->bus, sysfs_device->bus) != 0) {
				dbg(FIELD_BUS " is not matching");
				goto try_parent;
			}
			dbg(FIELD_BUS " matches");
		}

		/* check for matching bus id */
		if (rule->id[0] != '\0') {
			if (sysfs_device == NULL) {
				dbg("device has no sysfs_device");
				goto try_parent;
			}
			dbg("check " FIELD_ID);
			if (match_id(rule, sysfs_device) != 0) {
				dbg(FIELD_ID " is not matching");
				goto try_parent;
			}
			dbg(FIELD_ID " matches");
		}

		/* check for matching sysfs pairs */
		if (rule->sysfs_pair[0].file[0] != '\0') {
			dbg("check " FIELD_SYSFS " pairs");
			if (match_sysfs_pairs(rule, class_dev, sysfs_device) != 0) {
				dbg(FIELD_SYSFS " is not matching");
				goto try_parent;
			}
			dbg(FIELD_SYSFS " matches");
		}

		/* found matching physical device  */
		break;
try_parent:
		dbg("try parent sysfs device");
		sysfs_device = sysfs_get_device_parent(sysfs_device);
		if (sysfs_device == NULL)
			goto exit;
		dbg("sysfs_device->path='%s'", sysfs_device->path);
		dbg("sysfs_device->bus_id='%s'", sysfs_device->bus_id);
	}

	/* execute external program */
	if (rule->program[0] != '\0') {
		char program[PATH_SIZE];

		dbg("check " FIELD_PROGRAM);
		strlcpy(program, rule->program, sizeof(program));
		apply_format(udev, program, sizeof(program), class_dev, sysfs_device);
		if (execute_program(udev, program, udev->program_result, sizeof(udev->program_result)) != 0) {
			dbg(FIELD_PROGRAM " returned nonzero");
			goto try_parent;
		}
		dbg(FIELD_PROGRAM " returned successful");
	}

	/* check for matching result of external program */
	if (rule->result[0] != '\0') {
		dbg("check for " FIELD_RESULT "rule->result='%s', udev->program_result='%s'",
		   rule->result, udev->program_result);
		if (strcmp_pattern(rule->result, udev->program_result) != 0) {
			dbg(FIELD_RESULT " is not matching");
			goto try_parent;
		}
		dbg(FIELD_RESULT " matches");
	}

	/* rule matches */
	return 0;

exit:
	return -1;
}

int udev_rules_get_name(struct udevice *udev, struct sysfs_class_device *class_dev)
{
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_device *sysfs_device = NULL;
	struct udev_rule *rule;

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
	list_for_each_entry(rule, &udev_rule_list, node) {
		dbg("process rule");
		if (match_rule(udev, rule, class_dev, sysfs_device) == 0) {

			/* apply options */
			if (rule->ignore_device) {
				info("configured rule in '%s[%i]' applied, '%s' is ignored",
				     rule->config_file, rule->config_line, udev->kernel_name);
				return -1;
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
			if (rule->mode != 0000) {
				udev->mode = rule->mode;
				dbg("applied mode=%#o to '%s'", udev->mode, udev->kernel_name);
			}
			if (rule->owner[0] != '\0') {
				strlcpy(udev->owner, rule->owner, sizeof(udev->owner));
				apply_format(udev, udev->owner, sizeof(udev->owner), class_dev, sysfs_device);
				dbg("applied owner='%s' to '%s'", udev->owner, udev->kernel_name);
			}
			if (rule->group[0] != '\0') {
				strlcpy(udev->group, rule->group, sizeof(udev->group));
				apply_format(udev, udev->group, sizeof(udev->group), class_dev, sysfs_device);
				dbg("applied group='%s' to '%s'", udev->group, udev->kernel_name);
			}

			/* collect symlinks */
			if (rule->symlink[0] != '\0') {
				char temp[PATH_SIZE];
				char *pos, *next;

				info("configured rule in '%s[%i]' applied, added symlink '%s'",
				     rule->config_file, rule->config_line, rule->symlink);
				strlcpy(temp, rule->symlink, sizeof(temp));
				apply_format(udev, temp, sizeof(temp), class_dev, sysfs_device);

				/* add multiple symlinks separated by spaces */
				pos = temp;
				next = strchr(temp, ' ');
				while (next) {
					next[0] = '\0';
					dbg("add symlink '%s'", pos);
					name_list_add(&udev->symlink_list, pos, 0);
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				dbg("add symlink '%s'", pos);
				name_list_add(&udev->symlink_list, pos, 0);
			}

			/* rule matches */
			if (rule->name[0] != '\0') {
				info("configured rule in '%s[%i]' applied, '%s' becomes '%s'",
				     rule->config_file, rule->config_line, udev->kernel_name, rule->name);

				strlcpy(udev->name, rule->name, sizeof(udev->name));
				apply_format(udev, udev->name, sizeof(udev->name), class_dev, sysfs_device);
				strlcpy(udev->config_file, rule->config_file, sizeof(udev->config_file));
				udev->config_line = rule->config_line;

				if (udev->type != DEV_NET)
					dbg("name, '%s' is going to have owner='%s', group='%s', mode=%#o partitions=%i",
					    udev->name, udev->owner, udev->group, udev->mode, udev->partitions);

				break;
			}
		}
	}

	if (udev->name[0] == '\0') {
		/* no rule matched, so we use the kernel name */
		strlcpy(udev->name, udev->kernel_name, sizeof(udev->name));
		dbg("no rule found, use kernel name '%s'", udev->name);
	}

	if (udev->tmp_node[0] != '\0') {
		dbg("removing temporary device node");
		unlink_secure(udev->tmp_node);
		udev->tmp_node[0] = '\0';
	}

	return 0;
}
