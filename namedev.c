/*
 * namedev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
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

#include "list.h"
#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "libsysfs/libsysfs.h"
#include "klibc_fixups.h"

LIST_HEAD(config_device_list);

/* compare string with pattern (supports * ? [0-9] [!A-Z]) */
static int strcmp_pattern(const char *p, const char *s)
{
	if (*s == '\0') {
		while (*p == '*')
			p++;
		return (*p != '\0');
	}
	switch (*p) {
	case '[':
		{
			int not = 0;
			p++;
			if (*p == '!') {
				not = 1;
				p++;
			}
			while (*p && (*p != ']')) {
				int match = 0;
				if (p[1] == '-') {
					if ((*s >= *p) && (*s <= p[2]))
						match = 1;
					p += 3;
				} else {
					match = (*p == *s);
					p++;
				}
				if (match ^ not) {
					while (*p && (*p != ']'))
						p++;
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
		if (*s == '\0') {
			return 0;
		}
		break;
	default:
		if ((*p == *s) || (*p == '?'))
			return strcmp_pattern(p+1, s+1);
		break;
	}
	return 1;
}

#define copy_var(a, b, var)		\
	if (b->var)			\
		a->var = b->var;

#define copy_string(a, b, var)		\
	if (strlen(b->var))		\
		strcpy(a->var, b->var);

int add_config_dev(struct config_device *new_dev)
{
	struct list_head *tmp;
	struct config_device *tmp_dev;

	/* update the values if we already have the device */
	list_for_each(tmp, &config_device_list) {
		struct config_device *dev = list_entry(tmp, struct config_device, node);
		if (strcmp_pattern(new_dev->name, dev->name))
			continue;
		if (strncmp(dev->bus, new_dev->bus, sizeof(dev->name)))
			continue;
		copy_var(dev, new_dev, type);
		copy_var(dev, new_dev, mode);
		copy_string(dev, new_dev, bus);
		copy_string(dev, new_dev, sysfs_file);
		copy_string(dev, new_dev, sysfs_value);
		copy_string(dev, new_dev, id);
		copy_string(dev, new_dev, place);
		copy_string(dev, new_dev, kernel_name);
		copy_string(dev, new_dev, exec_program);
		copy_string(dev, new_dev, owner);
		copy_string(dev, new_dev, group);
		return 0;
	}

	/* not found, add new structure to the device list */
	tmp_dev = malloc(sizeof(*tmp_dev));
	if (!tmp_dev)
		return -ENOMEM;
	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add_tail(&tmp_dev->node, &config_device_list);
	//dump_config_dev(tmp_dev);
	return 0;
}

static mode_t get_default_mode(struct sysfs_class_device *class_dev)
{
	mode_t mode = 0600;	/* default to owner rw only */

	if (strlen(default_mode_str) != 0) {
		mode = strtol(default_mode_str, NULL, 8);
	}
	return mode;
}

static void build_kernel_number(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	char *dig;

	/* FIXME, figure out how to handle stuff like sdaj which will not work right now. */
	dig = class_dev->name + strlen(class_dev->name);
	while (isdigit(*(dig-1)))
		dig--;
	strfieldcpy(udev->kernel_number, dig);
	dbg("kernel_number='%s'", udev->kernel_number);
}

static void apply_format(struct udevice *udev, unsigned char *string)
{
	char name[NAME_SIZE];
	char *pos;

	while (1) {
		pos = strchr(string, '%');

		if (pos) {
			strfieldcpy(name, pos+2);
			*pos = 0x00;
			switch (pos[1]) {
			case 'b':
				if (strlen(udev->bus_id) == 0)
					break;
				strcat(pos, udev->bus_id);
				dbg("substitute bus_id '%s'", udev->bus_id);
				break;
			case 'n':
				if (strlen(udev->kernel_number) == 0)
					break;
				strcat(pos, udev->kernel_number);
				dbg("substitute kernel number '%s'", udev->kernel_number);
				break;
			case 'D':
				if (strlen(udev->kernel_number) == 0) {
					strcat(pos, "disk");
					break;
				}
				strcat(pos, "part");
				strcat(pos, udev->kernel_number);
				dbg("substitute kernel number '%s'", udev->kernel_number);
				break;
			case 'm':
				sprintf(pos, "%u", udev->minor);
				dbg("substitute minor number '%u'", udev->minor);
				break;
			case 'M':
				sprintf(pos, "%u", udev->major);
				dbg("substitute major number '%u'", udev->major);
				break;
			case 'c':
				if (strlen(udev->callout_value) == 0)
					break;
				strcat(pos, udev->callout_value);
				dbg("substitute callout output '%s'", udev->callout_value);
				break;
			default:
				dbg("unknown substitution type '%%%c'", pos[1]);
				break;
			}
			strcat(string, name);
		} else
			break;
	}
}


static int exec_callout(struct config_device *dev, char *value, int len)
{
	int retval;
	int res;
	int status;
	int fds[2];
	pid_t pid;
	int value_set = 0;
	char buffer[256];
	char *arg;
	char *args[CALLOUT_MAXARG];
	int i;

	dbg("callout to '%s'", dev->exec_program);
	retval = pipe(fds);
	if (retval != 0) {
		dbg("pipe failed");
		return -1;
	}
	pid = fork();
	if (pid == -1) {
		dbg("fork failed");
		return -1;
	}

	if (pid == 0) {
		/* child */
		close(STDOUT_FILENO);
		dup(fds[1]);	/* dup write side of pipe to STDOUT */
		if (strchr(dev->exec_program, ' ')) {
			/* callout with arguments */
			arg = dev->exec_program;
			for (i=0; i < CALLOUT_MAXARG-1; i++) {
				args[i] = strsep(&arg, " ");
				if (args[i] == NULL)
					break;
			}
			if (args[i]) {
				dbg("too many args - %d", i);
				args[i] = NULL;
			}
			retval = execve(args[0], args, main_envp);
		} else {
			retval = execve(dev->exec_program, main_argv, main_envp);
		}
		if (retval != 0) {
			dbg("child execve failed");
			exit(1);
		}
		return -1; /* avoid compiler warning */
	} else {
		/* parent reads from fds[0] */
		close(fds[1]);
		retval = 0;
		while (1) {
			res = read(fds[0], buffer, sizeof(buffer) - 1);
			if (res <= 0)
				break;
			buffer[res] = '\0';
			if (res > len) {
				dbg("callout len %d too short", len);
				retval = -1;
			}
			if (value_set) {
				dbg("callout value already set");
				retval = -1;
			} else {
				value_set = 1;
				strncpy(value, buffer, len);
			}
		}
		dbg("callout returned '%s'", value);
		close(fds[0]);
		res = wait(&status);
		if (res < 0) {
			dbg("wait failed result %d", res);
			retval = -1;
		}

#ifndef __KLIBC__
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("callout program status 0x%x", status);
			retval = -1;
		}
#endif
	}
	return retval;
}

static int do_callout(struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	struct config_device *dev;
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != CALLOUT)
			continue;

		if (sysfs_device) {
			dbg("dev->bus='%s' sysfs_device->bus='%s'", dev->bus, sysfs_device->bus);
			if (strcasecmp(dev->bus, sysfs_device->bus) != 0)
				continue;
		}

		/* substitute anything that needs to be in the program name */
		apply_format(udev, dev->exec_program);
		if (exec_callout(dev, udev->callout_value, NAME_SIZE))
			continue;
		if (strcmp_pattern(dev->id, udev->callout_value) != 0)
			continue;
		strfieldcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
		dbg("callout returned matching value '%s', '%s' becomes '%s'"
		    " - owner='%s', group='%s', mode=%#o",
		    dev->id, class_dev->name, udev->name,
		    dev->owner, dev->group, dev->mode);
		return 0;
	}
	return -ENODEV;
}

static int do_label(struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	struct sysfs_attribute *tmpattr = NULL;
	struct config_device *dev;
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != LABEL)
			continue;

		if (sysfs_device) {
			dbg("dev->bus='%s' sysfs_device->bus='%s'", dev->bus, sysfs_device->bus);
			if (strcasecmp(dev->bus, sysfs_device->bus) != 0)
				continue;
		}

		dbg("look for device attribute '%s'", dev->sysfs_file);
		/* try to find the attribute in the class device directory */
		tmpattr = sysfs_get_classdev_attr(class_dev, dev->sysfs_file);
		if (tmpattr)
			goto label_found;

		/* look in the class device directory if present */
		if (sysfs_device) {
			tmpattr = sysfs_get_device_attr(sysfs_device, dev->sysfs_file);
			if (tmpattr)
				goto label_found;
		}

		continue;

label_found:
		tmpattr->value[strlen(tmpattr->value)-1] = 0x00;
		dbg("compare attribute '%s' value '%s' with '%s'",
			  dev->sysfs_file, tmpattr->value, dev->sysfs_value);
		if (strcmp(dev->sysfs_value, tmpattr->value) != 0)
			continue;

		strfieldcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
		dbg("found matching attribute '%s', '%s' becomes '%s' "
			  "- owner='%s', group='%s', mode=%#o",
			  dev->sysfs_file, class_dev->name, udev->name,
			  dev->owner, dev->group, dev->mode);

		return 0;
	}
	return -ENODEV;
}

static int do_number(struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	struct config_device *dev;
	struct list_head *tmp;
	char path[SYSFS_PATH_MAX];
	int found;
	char *temp = NULL;

	/* we have to have a sysfs device for NUMBER to work */
	if (!sysfs_device)
		return -ENODEV;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != NUMBER)
			continue;

		dbg("dev->bus='%s' sysfs_device->bus='%s'", dev->bus, sysfs_device->bus);
		if (strcasecmp(dev->bus, sysfs_device->bus) != 0)
			continue;

		found = 0;
		strfieldcpy(path, sysfs_device->path);
		temp = strrchr(path, '/');
		dbg("search '%s' in '%s', path='%s'", dev->id, temp, path);
		if (strstr(temp, dev->id) != NULL) {
			found = 1;
		} else {
			*temp = 0x00;
			temp = strrchr(path, '/');
			dbg("search '%s' in '%s', path='%s'", dev->id, temp, path);
			if (strstr(temp, dev->id) != NULL)
				found = 1;
		}
		if (!found)
			continue;
		strfieldcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
		dbg("found matching id '%s', '%s' becomes '%s'"
		    " - owner='%s', group ='%s', mode=%#o",
		    dev->id, class_dev->name, udev->name,
		    dev->owner, dev->group, dev->mode);
		return 0;
	}
	return -ENODEV;
}

static int do_topology(struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	struct config_device *dev;
	struct list_head *tmp;
	char path[SYSFS_PATH_MAX];
	int found;
	char *temp = NULL;

	/* we have to have a sysfs device for TOPOLOGY to work */
	if (!sysfs_device)
		return -ENODEV;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != TOPOLOGY)
			continue;

		dbg("dev->bus='%s' sysfs_device->bus='%s'", dev->bus, sysfs_device->bus);
		if (strcasecmp(dev->bus, sysfs_device->bus) != 0)
			continue;

		found = 0;
		strfieldcpy(path, sysfs_device->path);
		temp = strrchr(path, '/');
		dbg("search '%s' in '%s', path='%s'", dev->place, temp, path);
		if (strstr(temp, dev->place) != NULL) {
			found = 1;
		} else {
			*temp = 0x00;
			temp = strrchr(path, '/');
			dbg("search '%s' in '%s', path='%s'", dev->place, temp, path);
			if (strstr(temp, dev->place) != NULL)
				found = 1;
		}
		if (!found)
			continue;

		strfieldcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
		dbg("found matching place '%s', '%s' becomes '%s'"
		    " - owner='%s', group ='%s', mode=%#o",
		    dev->place, class_dev->name, udev->name,
		    dev->owner, dev->group, dev->mode);
		return 0;
	}
	return -ENODEV;
}

static int do_replace(struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	struct config_device *dev;
	struct list_head *tmp;

	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		if (dev->type != REPLACE)
			continue;

		dbg("compare name '%s' with '%s'", dev->kernel_name, class_dev->name);
		if (strcmp_pattern(dev->kernel_name, class_dev->name) != 0)
			continue;

		strfieldcpy(udev->name, dev->name);
		if (dev->mode != 0) {
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
		dbg("found name, '%s' becomes '%s'"
		    " - owner='%s', group='%s', mode = %#o",
		    dev->kernel_name, udev->name,
		    dev->owner, dev->group, dev->mode);
		
		return 0;
	}
	return -ENODEV;
}

static void do_kernelname(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct config_device *dev;
	struct list_head *tmp;
	int len;

	strfieldcpy(udev->name, class_dev->name);
	/* look for permissions */
	list_for_each(tmp, &config_device_list) {
		dev = list_entry(tmp, struct config_device, node);
		len = strlen(dev->name);
		if (strcmp_pattern(dev->name, class_dev->name))
			continue;
		if (dev->mode != 0) {
			dbg("found permissions for '%s'", class_dev->name);
			udev->mode = dev->mode;
			strfieldcpy(udev->owner, dev->owner);
			strfieldcpy(udev->group, dev->group);
		}
	}
}

int namedev_name_device(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct sysfs_device *sysfs_device = NULL;
	struct sysfs_class_device *class_dev_parent = NULL;
	int retval = 0;
	char *temp = NULL;

	udev->mode = 0;

	/* find the sysfs_device for this class device */
	/* Wouldn't it really be nice if libsysfs could do this for us? */
	if (class_dev->sysdevice) {
		sysfs_device = class_dev->sysdevice;
	} else {
		/* bah, let's go backwards up a level to see if the device is there,
		 * as block partitions don't point to the physical device.  Need to fix that
		 * up in the kernel...
		 */
		if (strstr(class_dev->path, "block")) {
			dbg("looking at block device");
			if (isdigit(class_dev->path[strlen(class_dev->path)-1])) {
				char path[SYSFS_PATH_MAX];

				dbg("really is a partition");
				strfieldcpy(path, class_dev->path);
				temp = strrchr(path, '/');
				*temp = 0x00;
				dbg("looking for a class device at '%s'", path);
				class_dev_parent = sysfs_open_class_device(path);
				if (class_dev_parent == NULL) {
					dbg("sysfs_open_class_device at '%s' failed", path);
				} else {
					dbg("class_dev_parent->name='%s'", class_dev_parent->name);
					if (class_dev_parent->sysdevice)
						sysfs_device = class_dev_parent->sysdevice;
				}
			}
		}
	}
		
	if (sysfs_device) {
		dbg("sysfs_device->path='%s'", sysfs_device->path);
		dbg("sysfs_device->bus_id='%s'", sysfs_device->bus_id);
		dbg("sysfs_device->bus='%s'", sysfs_device->bus);
		strfieldcpy(udev->bus_id, sysfs_device->bus_id);
	} else {
		dbg("class_dev->name = '%s'", class_dev->name);
	}

	build_kernel_number(class_dev, udev);

	/* rules are looked at in priority order */
	retval = do_callout(class_dev, udev, sysfs_device);
	if (retval == 0)
		goto found;

	retval = do_label(class_dev, udev, sysfs_device);
	if (retval == 0)
		goto found;

	retval = do_number(class_dev, udev, sysfs_device);
	if (retval == 0)
		goto found;

	retval = do_topology(class_dev, udev, sysfs_device);
	if (retval == 0)
		goto found;

	retval = do_replace(class_dev, udev, sysfs_device);
	if (retval == 0)
		goto found;

	do_kernelname(class_dev, udev);
	goto done;

found:
	/* substitute placeholder in NAME  */
	apply_format(udev, udev->name);

done:
	/* mode was never set above */
	if (!udev->mode) {
		udev->mode = get_default_mode(class_dev);
		udev->owner[0] = 0x00;
		udev->group[0] = 0x00;
	}

	if (class_dev_parent)
		sysfs_close_class_device(class_dev_parent);

	return 0;
}

int namedev_init(void)
{
	int retval;
	
	retval = namedev_init_rules();
	if (retval)
		return retval;

	retval = namedev_init_permissions();
	if (retval)
		return retval;

	dump_config_dev_list();
	return retval;
}
