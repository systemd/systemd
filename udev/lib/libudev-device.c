/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_device {
	int refcount;
	struct udev *udev;
	char *devpath;
	char *syspath;
	char *devname;
	char *subsystem;
	struct list_head link_list;
	struct list_head env_list;
	char *action;
	char *driver;
	char *devpath_old;
	char *physdevpath;
	int timeout;
	dev_t devnum;
	unsigned long long int seqnum;
	int num_fake_partitions;
	int devlink_priority;
	int ignore_remove;
};

static size_t devpath_to_db_path(struct udev *udev, const char *devpath, char *filename, size_t len)
{
	size_t start;

	/* translate to location of db file */
	util_strlcpy(filename, udev_get_dev_path(udev), len);
	start = util_strlcat(filename, "/.udev/db/", len);
	util_strlcat(filename, devpath, len);
	return util_path_encode(&filename[start], len - start);
}

static int device_read_db(struct udev_device *udev_device)
{
	struct stat stats;
	char filename[UTIL_PATH_SIZE];
	char line[UTIL_LINE_SIZE];
	FILE *f;
	int rc = 0;

	devpath_to_db_path(udev_device->udev, udev_device->devpath, filename, sizeof(filename));

	if (lstat(filename, &stats) != 0) {
		info(udev_device->udev, "no db file to read %s: %s\n", filename, strerror(errno));
		return -1;
	}
	if ((stats.st_mode & S_IFMT) == S_IFLNK) {
		char target[UTIL_PATH_SIZE];
		int target_len;

		info(udev_device->udev, "found a symlink as db file\n");
		target_len = readlink(filename, target, sizeof(target));
		if (target_len > 0)
			target[target_len] = '\0';
		else {
			info(udev_device->udev, "error reading db link %s: %s\n", filename, strerror(errno));
			return -1;
		}
		dbg(udev_device->udev, "db link points to '%s'\n", target);
		if (asprintf(&udev_device->devname, "%s/%s", udev_get_dev_path(udev_device->udev), target) < 0)
			return -ENOMEM;
		return 0;
	}

	f = fopen(filename, "r");
	if (f == NULL) {
		info(udev_device->udev, "error reading db file %s: %s\n", filename, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		ssize_t len;
		const char *val;
		unsigned int maj, min;

		len = strlen(line);
		if (len < 4)
			break;
		line[len-1] = '\0';
		val = &line[2];

		switch(line[0]) {
		case 'N':
			asprintf(&udev_device->devname, "%s/%s", udev_get_dev_path(udev_device->udev), val);
			break;
		case 'M':
			sscanf(val, "%u:%u", &maj, &min);
			device_set_devnum(udev_device, makedev(maj, min));
			break;
		case 'S':
			util_strlcpy(filename, udev_get_dev_path(udev_device->udev), sizeof(filename));
			util_strlcat(filename, "/", sizeof(filename));
			util_strlcat(filename, val, sizeof(filename));
			device_add_devlink(udev_device, filename);
			break;
		case 'L':
			device_set_devlink_priority(udev_device, atoi(val));
			break;
		case 'T':
			device_set_timeout(udev_device,  atoi(val));
			break;
		case 'A':
			device_set_num_fake_partitions(udev_device, atoi(val));
			break;
		case 'R':
			device_set_ignore_remove(udev_device, atoi(val));
			break;
		case 'E':
			device_add_property(udev_device, val);
			break;
		}
	}
	fclose(f);

	return rc;
}

struct udev_device *device_init(struct udev *udev)
{
	struct udev_device *udev_device;

	if (udev == NULL)
		return NULL;

	udev_device = malloc(sizeof(struct udev_device));
	if (udev_device == NULL)
		return NULL;
	memset(udev_device, 0x00, sizeof(struct udev_device));
	udev_device->refcount = 1;
	udev_device->udev = udev;
	INIT_LIST_HEAD(&udev_device->link_list);
	INIT_LIST_HEAD(&udev_device->env_list);
	info(udev_device->udev, "udev_device: %p created\n", udev_device);
	return udev_device;
}

/**
 * udev_device_new_from_devpath:
 * @udev: udev library context
 * @devpath: sys device path
 *
 * Create new udev device, and fill in information from the sysfs
 * device and the udev database entry. The devpath must not contain
 * the sysfs mount path, and must contain a leading '/'.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the ressources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
struct udev_device *udev_device_new_from_devpath(struct udev *udev, const char *devpath)
{
	char path[UTIL_PATH_SIZE];
	struct stat statbuf;
	struct udev_device *udev_device;

	if (udev == NULL)
		return NULL;
	if (devpath == NULL)
		return NULL;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, devpath, sizeof(path));
	if (stat(path, &statbuf) != 0)
		return NULL;
	if (!S_ISDIR(statbuf.st_mode))
		return NULL;

	udev_device = device_init(udev);
	if (udev_device == NULL)
		return NULL;

	/* resolve possible symlink to real path */
	util_strlcpy(path, devpath, sizeof(path));
	util_resolve_sys_link(udev, path, sizeof(path));
	device_set_devpath(udev_device, path);
	info(udev, "device %p has devpath '%s'\n", udev_device, udev_device_get_devpath(udev_device));

	if (device_read_db(udev_device) >= 0)
		info(udev, "device %p filled with udev database data\n", udev_device);

	return udev_device;
}

/**
 * udev_device_get_udev:
 * @udev_device: udev device
 *
 * Retrieve the udev library context the device was created with.
 *
 * Returns: the udev library context
 **/
struct udev *udev_device_get_udev(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->udev;
}

/**
 * udev_device_ref:
 * @udev_device: udev device
 *
 * Take a reference of a udev device.
 *
 * Returns: the passed udev device
 **/
struct udev_device *udev_device_ref(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	udev_device->refcount++;
	return udev_device;
}

/**
 * udev_device_unref:
 * @udev_device: udev device
 *
 * Drop a reference of a udev device. If the refcount reaches zero,
 * the ressources of the device will be released.
 *
 **/
void udev_device_unref(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return;
	udev_device->refcount--;
	if (udev_device->refcount > 0)
		return;
	free(udev_device->syspath);
	free(udev_device->devname);
	free(udev_device->subsystem);
	util_name_list_cleanup(udev_device->udev, &udev_device->link_list);
	util_name_list_cleanup(udev_device->udev, &udev_device->env_list);
	free(udev_device->action);
	free(udev_device->driver);
	free(udev_device->devpath_old);
	free(udev_device->physdevpath);
	info(udev_device->udev, "udev_device: %p released\n", udev_device);
	free(udev_device);
}

/**
 * udev_device_get_devpath:
 * @udev_device: udev device
 *
 * Retrieve the kernel devpath value of the udev device. The path
 * does not contain the sys mount point, and starts with a '/'.
 *
 * Returns: the devpath of the udev device
 **/
const char *udev_device_get_devpath(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->devpath;
}

/**
 * udev_device_get_syspath:
 * @udev_device: udev device
 *
 * Retrieve the sys path of the udev device. The path is an
 * absolute path and starts with the sys mount point.
 *
 * Returns: the sys path of the udev device
 **/
const char *udev_device_get_syspath(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->syspath;
}

/**
 * udev_device_get_devname:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path is an absolute path, and starts with the device directory.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
const char *udev_device_get_devname(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->devname;
}

/**
 * udev_device_get_subsystem:
 * @udev_device: udev device
 *
 * Retrieve the subsystem string of the udev device. The string does not
 * contain any "/".
 *
 * Returns: the subsystem name of the udev device, or #NULL if it can not be determined
 **/
const char *udev_device_get_subsystem(struct udev_device *udev_device)
{
	char subsystem[UTIL_PATH_SIZE];

	if (udev_device == NULL)
		return NULL;
	if (udev_device->subsystem != NULL)
		return udev_device->subsystem;
	if (util_get_sys_subsystem(udev_device->udev, udev_device->devpath, subsystem, sizeof(subsystem)) < 2)
		return NULL;
	udev_device->subsystem = strdup(subsystem);
	return udev_device->subsystem;
}

/**
 * udev_device_get_devlinks:
 * @udev_device: udev device
 * @cb: function to be called for every device link found
 * @data: data to be passed to the function
 *
 * Retrieve the device links pointing to the device file of the
 * udev device. For every device link, the passed function will be
 * called with the device link string.
 * The path is an absolute path, and starts with the device directory.
 * If the function returns 1, remaning device links will be ignored.
 *
 * Returns: the number of device links passed to the caller, or a negative value on error
 **/
int udev_device_get_devlinks(struct udev_device *udev_device,
			      int (*cb)(struct udev_device *udev_device, const char *value, void *data),
			      void *data)
{
	struct util_name_entry *name_loop;
	int count = 0;

	if (udev_device == NULL)
		return -1;
	list_for_each_entry(name_loop, &udev_device->link_list, node) {
		count++;
		if (cb(udev_device, name_loop->name, data) != 0)
			break;
	}
	return count;
}

/**
 * udev_device_get_properties:
 * @udev_device: udev device
 * @cb: function to be called for every property found
 * @data: data to be passed to the function
 *
 * Retrieve the property key/value pairs belonging to the
 * udev device. For every key/value pair, the passed function will be
 * called. If the function returns 1, remaning properties will be
 * ignored.
 *
 * Returns: the number of properties passed to the caller, or a negative value on error
 **/
int udev_device_get_properties(struct udev_device *udev_device,
				int (*cb)(struct udev_device *udev_device, const char *key, const char *value, void *data),
				void *data)
{
	struct util_name_entry *name_loop;
	int count = 0;

	if (udev_device == NULL)
		return -1;
	list_for_each_entry(name_loop, &udev_device->env_list, node) {
		char name[UTIL_PATH_SIZE];
		char *val;

		strncpy(name, name_loop->name, sizeof(name));
		val = strchr(name, '=');
		if (val == NULL)
			continue;
		val[0] = '\0';
		val = &val[1];
		count++;
		if (cb(udev_device, name, val, data) != 0)
			break;
	}
	return count;
}

const char *udev_device_get_driver(struct udev_device *udev_device)
{
	char driver[UTIL_PATH_SIZE];

	if (udev_device == NULL)
		return NULL;
	if (udev_device->driver != NULL)
		return udev_device->driver;
	if (util_get_sys_driver(udev_device->udev, udev_device->devpath, driver, sizeof(driver)) < 2)
		return NULL;
	udev_device->driver = strdup(driver);
	return udev_device->driver;
}

dev_t udev_device_get_devnum(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return makedev(0, 0);
	return udev_device->devnum;
}

const char *udev_device_get_action(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->action;
}

unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return 0;
	return udev_device->seqnum;
}

int device_set_devpath(struct udev_device *udev_device, const char *devpath)
{
	if (asprintf(&udev_device->syspath, "%s%s", udev_get_sys_path(udev_device->udev), devpath) < 0)
		return -ENOMEM;
	udev_device->devpath = &udev_device->syspath[strlen(udev_get_sys_path(udev_device->udev))];
	return 0;
}

int device_set_subsystem(struct udev_device *udev_device, const char *subsystem)
{
	udev_device->subsystem = strdup(subsystem);
	if (udev_device->subsystem == NULL)
		return -1;
	return 0;
}

int device_set_devname(struct udev_device *udev_device, const char *devname)
{
	udev_device->devname = strdup(devname);
	if (udev_device->devname == NULL)
		return -ENOMEM;
	return 0;
}

int device_add_devlink(struct udev_device *udev_device, const char *devlink)
{
	if (util_name_list_add(udev_device->udev, &udev_device->link_list, devlink, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int device_add_property(struct udev_device *udev_device, const char *property)
{
	if (util_name_list_add(udev_device->udev, &udev_device->env_list, property, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int device_set_action(struct udev_device *udev_device, const char *action)
{
	udev_device->action = strdup(action);
	if (udev_device->action == NULL)
		return -ENOMEM;
	return 0;
}

int device_set_driver(struct udev_device *udev_device, const char *driver)
{
	udev_device->driver = strdup(driver);
	if (udev_device->driver == NULL)
		return -ENOMEM;
	return 0;
}

const char *device_get_devpath_old(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->devpath_old;
}

int device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old)
{
	udev_device->devpath_old = strdup(devpath_old);
	if (udev_device->devpath_old == NULL)
		return -ENOMEM;
	return 0;
}

const char *device_get_physdevpath(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->physdevpath;
}

int device_set_physdevpath(struct udev_device *udev_device, const char *physdevpath)
{
	udev_device->physdevpath = strdup(physdevpath);
	if (udev_device->physdevpath == NULL)
		return -ENOMEM;
	return 0;
}

int device_get_timeout(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return -1;
	return udev_device->timeout;
}

int device_set_timeout(struct udev_device *udev_device, int timeout)
{
	udev_device->timeout = timeout;
	return 0;
}

int device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum)
{
	udev_device->seqnum = seqnum;
	return 0;
}

int device_set_devnum(struct udev_device *udev_device, dev_t devnum)
{
	udev_device->devnum = devnum;
	return 0;
}

int device_get_num_fake_partitions(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return -1;
	return udev_device->num_fake_partitions;
}

int device_set_num_fake_partitions(struct udev_device *udev_device, int num)
{
	udev_device->num_fake_partitions = num;
	return 0;
}

int device_get_devlink_priority(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return -1;
	return udev_device->devlink_priority;
}

int device_set_devlink_priority(struct udev_device *udev_device, int prio)
{
	 udev_device->devlink_priority = prio;
	return 0;
}

int device_get_ignore_remove(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return -1;
	return udev_device->ignore_remove;
}

int device_set_ignore_remove(struct udev_device *udev_device, int ignore)
{
	udev_device->ignore_remove = ignore;
	return 0;
}

