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

#include "libsysfs/sysfs/libsysfs.h"
#include "list.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_version.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_db.h"


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

static int find_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device,
				const char *name, char *value, size_t len)
{
	struct sysfs_attribute *tmpattr;

	dbg("look for device attribute '%s'", name);
	if (class_dev) {
		tmpattr = sysfs_get_classdev_attr(class_dev, name);
		if (tmpattr)
			goto attr_found;
	}
	if (sysfs_device) {
		tmpattr = sysfs_get_device_attr(sysfs_device, name);
		if (tmpattr)
			goto attr_found;
	}

	return -1;

attr_found:
	strlcpy(value, tmpattr->value, len);
	remove_trailing_char(value, '\n');

	dbg("found attribute '%s'", tmpattr->path);
	return 0;
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
		case 's':
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
			replace_untrusted_chars(temp2);
			strlcat(string, temp2, maxsize);
			dbg("substitute sysfs value '%s'", temp2);
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
			err("unknown substitution type '%%%c'", c);
			break;
		}
		/* truncate to specified length */
		if (len > 0)
			pos[len] = '\0';

		strlcat(string, tail, maxsize);
	}
}

static int execute_program_pipe(const char *command, const char *subsystem, char *value, int len)
{
	int retval;
	int count;
	int status;
	int pipefds[2];
	pid_t pid;
	char *pos;
	char arg[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;

	strlcpy(arg, command, sizeof(arg));
	i = 0;
	if (strchr(arg, ' ')) {
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
		argv[1] = (char *) subsystem;
		argv[2] = NULL;
		dbg("execute '%s' with subsystem '%s' argument", arg, argv[1]);
	}

	retval = pipe(pipefds);
	if (retval != 0) {
		err("pipe failed");
		return -1;
	}

	pid = fork();
	switch(pid) {
	case 0:
		/* child dup2 write side of pipe to STDOUT */
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		dup2(pipefds[1], STDOUT_FILENO);
		retval = execv(arg, argv);
		err("exec of program failed");
		_exit(1);
	case -1:
		err("fork of '%s' failed", arg);
		retval = -1;
		break;
	default:
		/* parent reads from pipefds[0] */
		close(pipefds[1]);
		retval = 0;
		i = 0;
		while (1) {
			count = read(pipefds[0], value + i, len - i-1);
			if (count < 0) {
				err("read failed with '%s'", strerror(errno));
				retval = -1;
			}

			if (count == 0)
				break;

			i += count;
			if (i >= len-1) {
				err("result len %d too short", len);
				retval = -1;
				break;
			}
		}
		value[i] = '\0';

		close(pipefds[0]);
		waitpid(pid, &status, 0);

		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("exec program status 0x%x", status);
			retval = -1;
		}
	}

	if (!retval) {
		remove_trailing_char(value, '\n');
		dbg("result is '%s'", value);
		replace_untrusted_chars(value);
	} else
		value[0] = '\0';

	return retval;
}

static int match_rule(struct udevice *udev, struct udev_rule *rule,
		      struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	struct sysfs_device *parent_device = sysfs_device;

	if (rule->kernel_operation != KEY_OP_UNSET) {
		dbg("check for " KEY_KERNEL " rule->kernel='%s' udev_kernel_name='%s'",
		    rule->kernel, udev->kernel_name);
		if (strcmp_pattern(rule->kernel, udev->kernel_name) != 0) {
			dbg(KEY_KERNEL " is not matching");
			if (rule->kernel_operation != KEY_OP_NOMATCH)
				goto exit;
		} else {
			dbg(KEY_KERNEL " matches");
			if (rule->kernel_operation == KEY_OP_NOMATCH)
				goto exit;
		}
		dbg(KEY_KERNEL " key is true");
	}

	if (rule->subsystem_operation != KEY_OP_UNSET) {
		dbg("check for " KEY_SUBSYSTEM " rule->subsystem='%s' udev->subsystem='%s'",
		    rule->subsystem, udev->subsystem);
		if (strcmp_pattern(rule->subsystem, udev->subsystem) != 0) {
			dbg(KEY_SUBSYSTEM " is not matching");
			if (rule->subsystem_operation != KEY_OP_NOMATCH)
				goto exit;
		} else {
			dbg(KEY_SUBSYSTEM " matches");
			if (rule->subsystem_operation == KEY_OP_NOMATCH)
				goto exit;
		}
		dbg(KEY_SUBSYSTEM " key is true");
	}

	if (rule->env_pair_count) {
		int i;

		dbg("check for " KEY_ENV " pairs");
		for (i = 0; i < rule->env_pair_count; i++) {
			struct key_pair *pair;
			const char *value;

			pair = &rule->env_pair[i];
			value = getenv(pair->name);
			if (!value) {
				dbg(KEY_ENV "{'%s'} is not found", pair->name);
				goto exit;
			}
			if (strcmp_pattern(pair->value, value) != 0) {
				dbg(KEY_ENV "{'%s'} is not matching", pair->name);
				if (pair->operation != KEY_OP_NOMATCH)
					goto exit;
			} else {
				dbg(KEY_ENV "{'%s'} matches", pair->name);
				if (pair->operation == KEY_OP_NOMATCH)
					goto exit;
			}
		}
		dbg(KEY_ENV " key is true");
	}

	/* walk up the chain of physical devices and find a match */
	while (1) {
		/* check for matching driver */
		if (rule->driver_operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			dbg("check for " KEY_DRIVER " rule->driver='%s' sysfs_device->driver_name='%s'",
			    rule->driver, parent_device->driver_name);
			if (strcmp_pattern(rule->driver, parent_device->driver_name) != 0) {
				dbg(KEY_DRIVER " is not matching");
				if (rule->driver_operation != KEY_OP_NOMATCH)
					goto try_parent;
			} else {
				dbg(KEY_DRIVER " matches");
				if (rule->driver_operation == KEY_OP_NOMATCH)
					goto try_parent;
			}
			dbg(KEY_DRIVER " key is true");
		}

		/* check for matching bus value */
		if (rule->bus_operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			dbg("check for " KEY_BUS " rule->bus='%s' sysfs_device->bus='%s'",
			    rule->bus, parent_device->bus);
			if (strcmp_pattern(rule->bus, parent_device->bus) != 0) {
				dbg(KEY_BUS " is not matching");
				if (rule->bus_operation != KEY_OP_NOMATCH)
					goto try_parent;
			} else {
				dbg(KEY_BUS " matches");
				if (rule->bus_operation == KEY_OP_NOMATCH)
					goto try_parent;
			}
			dbg(KEY_BUS " key is true");
		}

		/* check for matching bus id */
		if (rule->id_operation != KEY_OP_UNSET) {
			if (parent_device == NULL) {
				dbg("device has no sysfs_device");
				goto exit;
			}
			dbg("check " KEY_ID);
			if (strcmp_pattern(rule->id, parent_device->bus_id) != 0) {
				dbg(KEY_ID " is not matching");
				if (rule->id_operation != KEY_OP_NOMATCH)
					goto try_parent;
			} else {
				dbg(KEY_ID " matches");
				if (rule->id_operation == KEY_OP_NOMATCH)
					goto try_parent;
			}
			dbg(KEY_ID " key is true");
		}

		/* check for matching sysfs pairs */
		if (rule->sysfs_pair_count) {
			int i;

			dbg("check " KEY_SYSFS " pairs");
			for (i = 0; i < rule->sysfs_pair_count; i++) {
				struct key_pair *pair;
				char value[VALUE_SIZE];
				size_t len;

				pair = &rule->sysfs_pair[i];
				if (find_sysfs_attribute(class_dev, parent_device, pair->name, value, sizeof(value)) != 0)
					goto try_parent;

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(pair->value);
				if (len && !isspace(pair->value[len-1])) {
					len = strlen(value);
					while (len > 0 && isspace(value[len-1]))
						value[--len] = '\0';
					dbg("removed %i trailing whitespace chars from '%s'", strlen(value)-len, value);
				}

				dbg("compare attribute '%s' value '%s' with '%s'", pair->name, value, pair->value);
				if (strcmp_pattern(pair->value, value) != 0) {
					dbg(KEY_SYSFS "{'%s'} is not matching", pair->name);
					if (pair->operation != KEY_OP_NOMATCH)
						goto try_parent;
				} else {
					dbg(KEY_SYSFS "{'%s'} matches", pair->name);
					if (pair->operation == KEY_OP_NOMATCH)
						goto try_parent;
				}
			}
			dbg(KEY_SYSFS " keys are true");
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
	if (rule->program_operation != KEY_OP_UNSET) {
		char program[PATH_SIZE];

		dbg("check " KEY_PROGRAM);
		strlcpy(program, rule->program, sizeof(program));
		apply_format(udev, program, sizeof(program), class_dev, sysfs_device);
		if (execute_program_pipe(program, udev->subsystem,
					 udev->program_result, sizeof(udev->program_result)) != 0) {
			dbg(KEY_PROGRAM " returned nonzero");
			if (rule->program_operation != KEY_OP_NOMATCH)
				goto exit;
		} else {
			dbg(KEY_PROGRAM " returned successful");
			if (rule->program_operation == KEY_OP_NOMATCH)
				goto exit;
		}
		dbg(KEY_PROGRAM " key is true");
	}

	/* check for matching result of external program */
	if (rule->result_operation != KEY_OP_UNSET) {
		dbg("check for " KEY_RESULT " rule->result='%s', udev->program_result='%s'",
		   rule->result, udev->program_result);
		if (strcmp_pattern(rule->result, udev->program_result) != 0) {
			dbg(KEY_RESULT " is not matching");
			if (rule->result_operation != KEY_OP_NOMATCH)
				goto exit;
		} else {
			dbg(KEY_RESULT " matches");
			if (rule->result_operation == KEY_OP_NOMATCH)
				goto exit;
		}
		dbg(KEY_RESULT " key is true");
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
					info("add symlink '%s'", pos);
					name_list_add(&udev->symlink_list, pos, 0);
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				info("add symlink '%s'", pos);
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

			if (rule->last_rule) {
				dbg("last rule to be applied");
				break;
			}

		}
	}

	if (udev->name[0] == '\0') {
		/* no rule matched, so we use the kernel name */
		strlcpy(udev->name, udev->kernel_name, sizeof(udev->name));
		info("no rule found, use kernel name '%s'", udev->name);
	}

	if (udev->tmp_node[0] != '\0') {
		dbg("removing temporary device node");
		unlink_secure(udev->tmp_node);
		udev->tmp_node[0] = '\0';
	}

	return 0;
}
