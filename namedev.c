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
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sysfs/libsysfs.h>

#include "list.h"
#include "udev.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "klibc_fixups.h"

static struct sysfs_attribute *find_sysfs_attribute(struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device, char *attr);

LIST_HEAD(config_device_list);
LIST_HEAD(perm_device_list);

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

#define copy_var(a, b, var)		\
	if (b->var)			\
		a->var = b->var;

#define copy_string(a, b, var)		\
	if (strlen(b->var))		\
		strcpy(a->var, b->var);

int add_perm_dev(struct perm_device *new_dev)
{
	struct perm_device *dev;
	struct perm_device *tmp_dev;

	/* update the values if we already have the device */
	list_for_each_entry(dev, &perm_device_list, node) {
		if (strcmp(new_dev->name, dev->name))
			continue;
		copy_var(dev, new_dev, mode);
		copy_string(dev, new_dev, owner);
		copy_string(dev, new_dev, group);
		return 0;
	}

	/* not found, add new structure to the perm list */
	tmp_dev = malloc(sizeof(*tmp_dev));
	if (!tmp_dev)
		return -ENOMEM;
	memcpy(tmp_dev, new_dev, sizeof(*tmp_dev));
	list_add_tail(&tmp_dev->node, &perm_device_list);
	//dump_perm_dev(tmp_dev);
	return 0;
}

static struct perm_device *find_perm(char *name)
{
	struct perm_device *perm;

	list_for_each_entry(perm, &perm_device_list, node) {
		if (strcmp_pattern(perm->name, name))
			continue;
		return perm;
	}
	return NULL;
}

static mode_t get_default_mode(void)
{
	mode_t mode = 0600;	/* default to owner rw only */

	if (strlen(default_mode_str) != 0)
		mode = strtol(default_mode_str, NULL, 8);

	return mode;
}

static char *get_default_owner(void)
{
	if (strlen(default_owner_str) == 0)
		strncpy(default_owner_str, "root", OWNER_SIZE);

	return default_owner_str;
}

static char *get_default_group(void)
{
	if (strlen(default_group_str) == 0)
		strncpy(default_group_str, "root", GROUP_SIZE);

	return default_group_str;
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
		if (tail != NULL) {
			*str = tail;
			dbg("format length=%i", num);
			return num;
		} else {
			dbg("format parsing error '%s'", *str);
		}
	}
	return -1;
}

static void apply_format(struct udevice *udev, unsigned char *string, struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	char temp[NAME_SIZE];
	char temp1[NAME_SIZE];
	char *tail;
	char *pos;
	char *pos2;
	char *pos3;
	char *attr;
	int num;
	int i;
	char c;
	struct sysfs_attribute *tmpattr;

	pos = string;

	while (1) {
		pos = strchr(pos, '%');
		if (pos != NULL) {
			pos[0] = '\0';
			tail = pos+1;
			num = get_format_len(&tail);
			c = tail[0];
			strfieldcpy(temp, tail+1);
			tail = temp;
		} else {
			break;
		}
		dbg("format=%c, string='%s', tail='%s'",c , string, tail);

		attr = get_format_attribute(&tail);

		switch (c) {
		case 'b':
			if (strlen(udev->bus_id) == 0)
				break;
			strcat(pos, udev->bus_id);
			dbg("substitute bus_id '%s'", udev->bus_id);
			break;
		case 'k':
			if (strlen(udev->kernel_name) == 0)
				break;
			strcat(pos, udev->kernel_name);
			dbg("substitute kernel name '%s'", udev->kernel_name);
			break;
		case 'n':
			if (strlen(udev->kernel_number) == 0)
				break;
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
			if (strlen(udev->program_result) == 0)
				break;
			/* get part part of the result string */
			i = num; /* num syntax is deprecated and will be removed  */
			if (attr != NULL)
				i = atoi(attr);
			if (i > 0) {
				strncpy(temp1, udev->program_result, sizeof(temp1));
				pos2 = temp1;
				while (i) {
					i--;
					pos3 = strsep(&pos2, " ");
					if (pos3 == NULL) {
						dbg("requested part of result string not found");
						break;
					}
				}
				if (pos3) {
					strcat(pos, pos3);
					dbg("substitute part of result string '%s'", pos3);
				}
			} else {
				strcat(pos, udev->program_result);
				dbg("substitute result string '%s'", udev->program_result);
			}
			break;
		case 's':
			if (attr != NULL) {
				tmpattr = find_sysfs_attribute(class_dev, sysfs_device, attr);
				if (tmpattr == NULL) {
					dbg("sysfa attribute '%s' not found", attr);
					break;
				}
				strcpy(pos, tmpattr->value);
				dbg("substitute sysfs value '%s'", tmpattr->value);
			} else {
				dbg("missing attribute");
			}
			break;
		case '%':
			strcat(pos, "%");
			break;
		default:
			dbg("unknown substitution type '%%%c'", c);
			break;
		}
		strcat(pos, tail);
	}
}

/* 
 * Note, we can have multiple files for different busses in here due
 * to the mess that USB has for its device tree...
 */
static struct bus_file {
	char *bus;
	char *file;
} bus_files[] = {
	{ .bus = "scsi",	.file = "vendor" },
	{ .bus = "usb",		.file = "idVendor" },
	{ .bus = "usb",		.file = "iInterface" },
	{ .bus = "usb-serial",	.file = "detach_state" },
	{ .bus = "ide",		.file = "detach_state" },
	{ .bus = "pci",		.file = "vendor" },
	{}
};

#define SECONDS_TO_WAIT_FOR_FILE	10
static void wait_for_device_to_initialize(struct sysfs_device *sysfs_device)
{
	/* sleep until we see the file for this specific bus type show up this
	 * is needed because we can easily out-run the kernel in looking for
	 * these files before the paticular subsystem has created them in the
	 * sysfs tree properly.
	 *
	 * And people thought that the /sbin/hotplug event system was going to
	 * be slow, poo on you for arguing that before even testing it...
	 */
	struct bus_file *b = &bus_files[0];
	struct sysfs_attribute *tmpattr;
	int found = 0;
	int loop = SECONDS_TO_WAIT_FOR_FILE;

	while (1) {
		if (b->bus == NULL) {
			if (!found)
				break;
			/* sleep to give the kernel a chance to create the file */
			sleep(1);
			--loop;
			if (loop == 0)
				break;
			b = &bus_files[0];
		}
		if (strcmp(sysfs_device->bus, b->bus) == 0) {
			found = 1;
			dbg("looking for file '%s' on bus '%s'", b->file, b->bus);
			tmpattr = sysfs_get_device_attr(sysfs_device, b->file);
			if (tmpattr) {
				/* found it! */
				goto exit;
			}
			dbg("can't find '%s' file", b->file);
		}
		++b;
	}
	if (!found)
		dbg("did not find bus type '%s' on list of bus_id_files, "
		    "contact greg@kroah.com", sysfs_device->bus);
exit:
	return; /* here to prevent compiler warning... */
}

static void fix_kernel_name(struct udevice *udev)
{
	char *temp = udev->kernel_name;

	while (*temp != 0x00) {
		/* Some block devices have a ! in their name, 
		 * we need to change that to / */
		if (*temp == '!')
			*temp = '/';
		++temp;
	}
}

static int execute_program(char *path, char *value, int len)
{
	int retval;
	int res;
	int status;
	int fds[2];
	pid_t pid;
	int value_set = 0;
	char buffer[256];
	char *pos;
	char *args[PROGRAM_MAXARG];
	int i;

	dbg("executing '%s'", path);
	retval = pipe(fds);
	if (retval != 0) {
		dbg("pipe failed");
		return -1;
	}
	pid = fork();
	switch(pid) {
	case 0:
		/* child */
		close(STDOUT_FILENO);
		dup(fds[1]);	/* dup write side of pipe to STDOUT */
		if (strchr(path, ' ')) {
			/* exec with arguments */
			pos = path;
			for (i=0; i < PROGRAM_MAXARG-1; i++) {
				args[i] = strsep(&pos, " ");
				if (args[i] == NULL)
					break;
			}
			if (args[i]) {
				dbg("too many args - %d", i);
				args[i] = NULL;
			}
			retval = execv(args[0], args);
		} else {
			retval = execv(path, main_argv);
		}
		dbg("child execve failed");
		exit(1);
	case -1:
		dbg("fork failed");
		return -1;
	default:
		/* parent reads from fds[0] */
		close(fds[1]);
		retval = 0;
		while (1) {
			res = read(fds[0], buffer, sizeof(buffer) - 1);
			if (res <= 0)
				break;
			buffer[res] = '\0';
			if (res > len) {
				dbg("result len %d too short", len);
				retval = -1;
			}
			if (value_set) {
				dbg("result value already set");
				retval = -1;
			} else {
				value_set = 1;
				strncpy(value, buffer, len);
				pos = value + strlen(value)-1;
				if (pos[0] == '\n')
				pos[0] = '\0';
				dbg("result is '%s'", value);
			}
		}
		close(fds[0]);
		res = wait(&status);
		if (res < 0) {
			dbg("wait failed result %d", res);
			retval = -1;
		}

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

	if ((pair == NULL) || (pair->file[0] == '\0') || (pair->value == '\0'))
		return -ENODEV;

	tmpattr = find_sysfs_attribute(class_dev, sysfs_device, pair->file);
	if (tmpattr == NULL)
		return -ENODEV;

	dbg("compare attribute '%s' value '%s' with '%s'",
		  pair->file, tmpattr->value, pair->value);
	if (strcmp_pattern(pair->value, tmpattr->value) != 0)
		return -ENODEV;

	dbg("found matching attribute '%s' with value '%s'",
	    pair->file, pair->value);
	return 0;
}

static int match_sysfs_pairs(struct config_device *dev, struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	struct sysfs_pair *pair;
	int i;

	for (i = 0; i < MAX_SYSFS_PAIRS; ++i) {
		pair = &dev->sysfs_pair[i];
		if ((pair->file[0] == '\0') || (pair->value[0] == '\0'))
			break;
		if (compare_sysfs_attribute(class_dev, sysfs_device, pair) != 0) {
			dbg("sysfs attribute doesn't match");
			return -ENODEV;
		}
	}

	return 0;
}

static int match_id(struct config_device *dev, struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	char path[SYSFS_PATH_MAX];
	char *temp = NULL;

	/* we have to have a sysfs device for ID to work */
	if (!sysfs_device)
		return -ENODEV;

	strfieldcpy(path, sysfs_device->path);
	temp = strrchr(path, '/');
	temp++;
	dbg("search '%s' in '%s', path='%s'", dev->id, temp, path);
	if (strcmp_pattern(dev->id, temp) != 0)
		return -ENODEV;
	else
		return 0;
}

static int match_place(struct config_device *dev, struct sysfs_class_device *class_dev, struct sysfs_device *sysfs_device)
{
	char path[SYSFS_PATH_MAX];
	int found;
	char *temp = NULL;

	/* we have to have a sysfs device for PLACE to work */
	if (!sysfs_device)
		return -ENODEV;

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
	if (!found) {
		dbg("place doesn't match");
		return -ENODEV;
	}

	return 0;
}

static struct sysfs_device *get_sysfs_device(struct sysfs_class_device *class_dev)
{
	struct sysfs_device *sysfs_device;
	struct sysfs_class_device *class_dev_parent;
	struct timespec tspec;
	int loop;

	/* Figure out where the device symlink is at.  For char devices this will
	 * always be in the class_dev->path.  But for block devices, it's different.
	 * The main block device will have the device symlink in it's path, but
	 * all partitions have the symlink in its parent directory.
	 * But we need to watch out for block devices that do not have parents, yet
	 * look like a partition (fd0, loop0, etc.)  They all do not have a device
	 * symlink yet.  We do sit and spin on waiting for them right now, we should
	 * possibly have a whitelist for these devices here...
	 */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent) 
		dbg("Really a partition");

	tspec.tv_sec = 0;
	tspec.tv_nsec = 10000000;  /* sleep 10 millisec */
	loop = 10;
	while (loop--) {
		if (udev_sleep)
			nanosleep(&tspec, NULL);
		if (class_dev_parent)
			sysfs_device = sysfs_get_classdev_device(class_dev_parent);
		else
			sysfs_device = sysfs_get_classdev_device(class_dev);

		if (sysfs_device != NULL)
			goto device_found;
	}
	dbg("timed out waiting for device symlink, continuing on anyway...");
	
device_found:
        /* We have another issue with just the wait above - the sysfs part of
	 * the kernel may not be quick enough to have created the link to the
	 * device under the "bus" subsystem. Due to this, the sysfs_device->bus
	 * will not contain the actual bus name :(
	 *
	 * Libsysfs now provides a new API sysfs_get_device_bus(), so use it
	 * if needed
	 */
        if (sysfs_device) {
		if (sysfs_device->bus[0] != '\0')
			goto bus_found;

		loop = 10;
		tspec.tv_nsec = 10000000;
		while (loop--) {
			if (udev_sleep)
				nanosleep(&tspec, NULL);
			sysfs_get_device_bus(sysfs_device);
			
			if (sysfs_device->bus[0] != '\0')
				goto bus_found;
		}
		dbg("timed out waiting to find the device bus, continuing on anyway");
		goto exit;
bus_found:
		dbg("device %s is registered with bus '%s'",
				sysfs_device->name, sysfs_device->bus);
	}
exit:
	return sysfs_device;
}

static int match_rule(struct config_device *dev, struct sysfs_class_device *class_dev, struct udevice *udev, struct sysfs_device *sysfs_device)
{
	while (1) {
		/* check for matching bus value */
		if (dev->bus[0] != '\0') {
			if (sysfs_device == NULL) {
				dbg("device has no bus");
				goto try_parent;
			}
			dbg("check for " FIELD_BUS " dev->bus='%s' sysfs_device->bus='%s'", dev->bus, sysfs_device->bus);
			if (strcmp_pattern(dev->bus, sysfs_device->bus) != 0) {
				dbg(FIELD_BUS " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_BUS " matches");
			}
		}

		/* check for matching kernel name*/
		if (dev->kernel[0] != '\0') {
			dbg("check for " FIELD_KERNEL " dev->kernel='%s' class_dev->name='%s'", dev->kernel, class_dev->name);
			if (strcmp_pattern(dev->kernel, class_dev->name) != 0) {
				dbg(FIELD_KERNEL " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_KERNEL " matches");
			}
		}

		/* check for matching bus id */
		if (dev->id[0] != '\0') {
			dbg("check " FIELD_ID);
			if (match_id(dev, class_dev, sysfs_device) != 0) {
				dbg(FIELD_ID " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_ID " matches");
			}
		}

		/* check for matching place of device */
		if (dev->place[0] != '\0') {
			dbg("check " FIELD_PLACE);
			if (match_place(dev, class_dev, sysfs_device) != 0) {
				dbg(FIELD_PLACE " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_PLACE " matches");
			}
		}

		/* check for matching sysfs pairs */
		if (dev->sysfs_pair[0].file[0] != '\0') {
			dbg("check " FIELD_SYSFS " pairs");
			if (match_sysfs_pairs(dev, class_dev, sysfs_device) != 0) {
				dbg(FIELD_SYSFS " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_SYSFS " matches");
			}
		}

		/* execute external program */
		if (dev->program[0] != '\0') {
			dbg("check " FIELD_PROGRAM);
			apply_format(udev, dev->program, class_dev, sysfs_device);
			if (execute_program(dev->program, udev->program_result, NAME_SIZE) != 0) {
				dbg(FIELD_PROGRAM " returned nozero");
				goto try_parent;
			} else {
				dbg(FIELD_PROGRAM " returned successful");
			}
		}

		/* check for matching result of external program */
		if (dev->result[0] != '\0') {
			dbg("check for " FIELD_RESULT
			    " dev->result='%s', udev->program_result='%s'",
			    dev->result, udev->program_result);
			if (strcmp_pattern(dev->result, udev->program_result) != 0) {
				dbg(FIELD_RESULT " is not matching");
				goto try_parent;
			} else {
				dbg(FIELD_RESULT " matches");
			}
		}

		/* Yeah, we matched! */
		return 0;

try_parent:
		dbg("try parent sysfs device");
		sysfs_device = sysfs_get_device_parent(sysfs_device);
		if (sysfs_device == NULL)
			return -ENODEV;
		dbg("sysfs_device->path='%s'", sysfs_device->path);
		dbg("sysfs_device->bus_id='%s'", sysfs_device->bus_id);
		dbg("sysfs_device->bus='%s'", sysfs_device->bus);
	}

}

int namedev_name_device(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	struct sysfs_device *sysfs_device = NULL;
	struct config_device *dev;
	struct perm_device *perm;
	char *pos;

	udev->mode = 0;

	/* find the sysfs_device associated with this class device */
	sysfs_device = get_sysfs_device(class_dev);
	if (sysfs_device) {
		dbg("sysfs_device->path='%s'", sysfs_device->path);
		dbg("sysfs_device->bus_id='%s'", sysfs_device->bus_id);
		dbg("sysfs_device->bus='%s'", sysfs_device->bus);
		strfieldcpy(udev->bus_id, sysfs_device->bus_id);
		wait_for_device_to_initialize(sysfs_device);
	}
	dbg("class_dev->name = '%s'", class_dev->name);

	strfieldcpy(udev->kernel_name, class_dev->name);
	fix_kernel_name(udev);
	dbg("udev->kernel_name = '%s'", udev->kernel_name);

	/* get kernel number */
	pos = class_dev->name + strlen(class_dev->name);
	while (isdigit(*(pos-1)))
		pos--;
	strfieldcpy(udev->kernel_number, pos);
	dbg("kernel_number='%s'", udev->kernel_number);

	/* look for a matching rule to apply */
	list_for_each_entry(dev, &config_device_list, node) {
		dbg("process rule");
		if (match_rule(dev, class_dev, udev, sysfs_device) == 0) {
			if (dev->name[0] == '\0') {
				info("configured rule in '%s' at line %i applied, '%s' is ignored",
				     udev_rules_filename, dev->config_line, udev->kernel_name);
				return -1;
			}

			info("configured rule in '%s' at line %i applied, '%s' becomes '%s'",
			     udev_rules_filename, dev->config_line, udev->kernel_name, dev->name);
			strfieldcpy(udev->name, dev->name);
			strfieldcpy(udev->symlink, dev->symlink);
			goto found;
		}
	}

	/* no rule was found so we use the kernel name */
	strfieldcpy(udev->name, udev->kernel_name);
	goto done;

found:
	/* substitute placeholder */
	apply_format(udev, udev->name, class_dev, sysfs_device);
	apply_format(udev, udev->symlink, class_dev, sysfs_device);
	udev->partitions = dev->partitions;
done:
	perm = find_perm(udev->name);
	if (perm) {
		udev->mode = perm->mode;
		strfieldcpy(udev->owner, perm->owner);
		strfieldcpy(udev->group, perm->group);
	} else {
		/* no matching perms found :( */
		udev->mode = get_default_mode();
		strncpy(udev->owner, get_default_owner(), OWNER_SIZE);
		strncpy(udev->group, get_default_group(), GROUP_SIZE);
	}
	dbg("name, '%s' is going to have owner='%s', group='%s', mode = %#o",
	    udev->name, udev->owner, udev->group, udev->mode);

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
	dump_perm_dev_list();
	return retval;
}
