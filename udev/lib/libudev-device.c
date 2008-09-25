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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_device {
	int refcount;
	struct udev *udev;
	struct udev_device *parent_device;
	char *syspath;
	const char *devpath;
	const char *sysname;
	char *devname;
	char *subsystem;
	struct list_head link_list;
	struct list_head properties_list;
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
	struct list_head attr_list;
};

static size_t syspath_to_db_path(struct udev_device *udev_device, char *filename, size_t len)
{
	size_t start;

	/* translate to location of db file */
	util_strlcpy(filename, udev_get_dev_path(udev_device->udev), len);
	start = util_strlcat(filename, "/.udev/db/", len);
	util_strlcat(filename, udev_device->devpath, len);
	return util_path_encode(&filename[start], len - start);
}

static int device_read_uevent_file(struct udev_device *udev_device)
{
	char filename[UTIL_PATH_SIZE];
	FILE *f;
	char line[UTIL_LINE_SIZE];
	int maj = 0;
	int min = 0;

	util_strlcpy(filename, udev_device->syspath, sizeof(filename));
	util_strlcat(filename, "/uevent", sizeof(filename));
	f = fopen(filename, "r");
	if (f == NULL)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		pos = strchr(line, '\n');
		if (pos == NULL)
			continue;
		pos[0] = '\0';

		if (strncmp(line, "MAJOR=", 6) == 0)
			maj = strtoull(&line[6], NULL, 10);
		else if (strncmp(line, "MINOR=", 6) == 0)
			min = strtoull(&line[6], NULL, 10);

		device_add_property_from_string(udev_device, line);
	}

	udev_device->devnum = makedev(maj, min);

	fclose(f);
	return 0;
}

static int device_read_db(struct udev_device *udev_device)
{
	struct stat stats;
	char filename[UTIL_PATH_SIZE];
	char line[UTIL_LINE_SIZE];
	FILE *f;

	syspath_to_db_path(udev_device, filename, sizeof(filename));

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

		len = strlen(line);
		if (len < 4)
			break;
		line[len-1] = '\0';
		val = &line[2];

		switch(line[0]) {
		case 'N':
			asprintf(&udev_device->devname, "%s/%s", udev_get_dev_path(udev_device->udev), val);
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
			device_set_timeout(udev_device, atoi(val));
			break;
		case 'A':
			device_set_num_fake_partitions(udev_device, atoi(val));
			break;
		case 'R':
			device_set_ignore_remove(udev_device, atoi(val));
			break;
		case 'E':
			device_add_property_from_string(udev_device, val);
			break;
		}
	}
	fclose(f);

	info(udev_device->udev, "device %p filled with udev database data\n", udev_device);
	return 0;
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
	INIT_LIST_HEAD(&udev_device->properties_list);
	INIT_LIST_HEAD(&udev_device->attr_list);
	info(udev_device->udev, "udev_device: %p created\n", udev_device);
	return udev_device;
}

/**
 * udev_device_new_from_syspath:
 * @udev: udev library context
 * @syspath: sys device path including sys directory
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The sypath is the absolute
 * path to the device, including the sys mount point.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the ressources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath)
{
	char path[UTIL_PATH_SIZE];
	struct stat statbuf;
	struct udev_device *udev_device;

	if (udev == NULL)
		return NULL;
	if (syspath == NULL)
		return NULL;

	util_strlcpy(path, syspath, sizeof(path));
	util_strlcat(path, "/uevent", sizeof(path));
	if (stat(path, &statbuf) != 0) {
		info(udev, "not a device :%s\n", syspath);
		return NULL;
	}

	udev_device = device_init(udev);
	if (udev_device == NULL)
		return NULL;

	/* resolve possible symlink to real path */
	util_strlcpy(path, syspath, sizeof(path));
	util_resolve_sys_link(udev, path, sizeof(path));
	device_set_syspath(udev_device, path);
	info(udev, "device %p has devpath '%s'\n", udev_device, udev_device_get_devpath(udev_device));

	device_read_uevent_file(udev_device);
	device_read_db(udev_device);
	return udev_device;
}

struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum)
{
	char path[UTIL_PATH_SIZE];
	const char *type_str;
	struct udev_enumerate *enumerate;
	struct udev_list *list;
	struct udev_device *device = NULL;

	if (type == 'b')
		type_str = "block";
	else if (type == 'c')
		type_str = "char";
	else
		return NULL;

	/* /sys/dev/{block,char}/<maj>:<min> links */
	snprintf(path, sizeof(path), "%s/dev/%s/%u:%u", udev_get_sys_path(udev),
		 type_str, major(devnum), minor(devnum));
	if (util_resolve_sys_link(udev, path, sizeof(path)) == 0)
		return udev_device_new_from_syspath(udev, path);

	/* fallback to search all sys devices for the major/minor */
	enumerate = udev_enumerate_new_from_subsystems(udev, NULL);
	if (enumerate == NULL)
		return NULL;
	list = udev_enumerate_get_devices_list(enumerate);
	while (list != NULL) {
		struct udev_device *device_loop;

		device_loop = udev_device_new_from_syspath(udev, udev_list_get_name(list));
		if (device_loop != NULL) {
			if (udev_device_get_devnum(device_loop) == devnum) {
				device = device_loop;
				break;
			}
			udev_device_unref(device_loop);
		}
		list = udev_list_get_next(list);
	}
	udev_enumerate_unref(enumerate);
	return device;
}

static struct udev_device *device_new_from_parent(struct udev_device *udev_device)
{
	struct udev_device *udev_device_parent = NULL;
	char path[UTIL_PATH_SIZE];
	char *pos;

	if (udev_device == NULL)
		return NULL;

	util_strlcpy(path, udev_device->syspath, sizeof(path));
	while (1) {
		pos = strrchr(path, '/');
		if (pos == path || pos == NULL)
			break;
		pos[0] = '\0';
		udev_device_parent = udev_device_new_from_syspath(udev_device->udev, path);
		if (udev_device_parent != NULL)
			return udev_device_parent;
	}

	/* follow "device" link in deprecated sys /sys/class/ layout */
	if (strncmp(udev_device->devpath, "/class/", 7) == 0) {
		util_strlcpy(path, udev_device->syspath, sizeof(path));
		util_strlcat(path, "/device", sizeof(path));
		if (util_resolve_sys_link(udev_device->udev, path, sizeof(path)) == 0) {
			udev_device_parent = udev_device_new_from_syspath(udev_device->udev, path);
			if (udev_device_parent != NULL)
				return udev_device_parent;
		}
	}
	return NULL;
}

struct udev_device *udev_device_get_parent(struct udev_device *udev_device)
{
	if (udev_device->parent_device != NULL) {
		info(udev_device->udev, "returning existing parent %p\n", udev_device->parent_device);
		return udev_device->parent_device;
	}
	udev_device->parent_device = device_new_from_parent(udev_device);
	return udev_device->parent_device;
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
	if (udev_device->parent_device != NULL)
		udev_device_unref(udev_device->parent_device);
	free(udev_device->syspath);
	free(udev_device->devname);
	free(udev_device->subsystem);
	list_cleanup(udev_device->udev, &udev_device->link_list);
	list_cleanup(udev_device->udev, &udev_device->properties_list);
	free(udev_device->action);
	free(udev_device->driver);
	free(udev_device->devpath_old);
	free(udev_device->physdevpath);
	list_cleanup(udev_device->udev, &udev_device->attr_list);
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

const char *udev_device_get_sysname(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->sysname;
}

/**
 * udev_device_get_devnode:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path is an absolute path, and starts with the device directory.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
const char *udev_device_get_devnode(struct udev_device *udev_device)
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
	char subsystem[UTIL_NAME_SIZE];

	if (udev_device == NULL)
		return NULL;
	if (udev_device->subsystem != NULL)
		return udev_device->subsystem;

	/* read "subsytem" link */
	if (util_get_sys_subsystem(udev_device->udev, udev_device->syspath, subsystem, sizeof(subsystem)) > 0) {
		udev_device->subsystem = strdup(subsystem);
		return udev_device->subsystem;
	}

	/* implicit names */
	if (strncmp(udev_device->devpath, "/module/", 8) == 0) {
		udev_device->subsystem = strdup("module");
		return udev_device->subsystem;
	}
	if (strstr(udev_device->devpath, "/drivers/") != NULL) {
		udev_device->subsystem = strdup("drivers");
		return udev_device->subsystem;
	}
	if (strncmp(udev_device->devpath, "/subsystem/", 11) == 0 ||
	    strncmp(udev_device->devpath, "/class/", 7) == 0 ||
	    strncmp(udev_device->devpath, "/bus/", 5) == 0) {
		udev_device->subsystem = strdup("subsystem");
		return udev_device->subsystem;
	}
	return NULL;
}

/**
 * udev_device_get_devlinks_list:
 * @udev_device: udev device
 *
 * Retrieve the list of device links pointing to the device file of
 * the udev device. The next list entry can be retrieved with
 * udev_list_next(), which returns #NULL if no more entries exist.
 * The devlink path can be retrieved from the list entry by
 * udev_list_get_name(). The path is an absolute path, and starts with
 * the device directory.
 *
 * Returns: the first entry of the device node link list
 **/
struct udev_list *udev_device_get_devlinks_list(struct udev_device *udev_device)
{
	return list_get_entry(&udev_device->link_list);
}

/**
 * udev_device_get_properties_list:
 * @udev_device: udev device
 *
 * Retrieve the list of key/value device properties of the udev
 * device. The next list entry can be retrieved with udev_list_next(),
 * which returns #NULL if no more entries exist. The property name
 * can be retrieved from the list entry by udev_list_get_name(),
 * the property value by udev_list_get_value().
 *
 * Returns: the first entry of the property list
 **/
struct udev_list *udev_device_get_properties_list(struct udev_device *udev_device)
{
	return list_get_entry(&udev_device->properties_list);
}

const char *udev_device_get_driver(struct udev_device *udev_device)
{
	char driver[UTIL_NAME_SIZE];

	if (udev_device == NULL)
		return NULL;
	if (udev_device->driver != NULL)
		return udev_device->driver;
	if (util_get_sys_driver(udev_device->udev, udev_device->syspath, driver, sizeof(driver)) < 2)
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

const char *udev_device_get_attr_value(struct udev_device *udev_device, const char *attr)
{
	struct udev_list *list;
	char path[UTIL_PATH_SIZE];
	char value[UTIL_NAME_SIZE];
	struct stat statbuf;
	int fd;
	ssize_t size;
	const char *val = NULL;

	/* look for possibly already cached result */
	list = list_get_entry(&udev_device->attr_list);
	while (list != NULL) {
		if (strcmp(udev_list_get_name(list), attr) == 0) {
			info(udev_device->udev, "got '%s' (%s) from cache\n", attr, udev_list_get_value(list));
			return udev_list_get_name(list);
		}
		list = udev_list_get_next(list);
	}

	util_strlcpy(path, udev_device_get_syspath(udev_device), sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, attr, sizeof(path));

	if (lstat(path, &statbuf) != 0) {
		info(udev_device->udev, "stat '%s' failed: %s\n", path, strerror(errno));
		goto out;
	}

	if (S_ISLNK(statbuf.st_mode)) {
		/* links return the last element of the target path */
		char target[UTIL_NAME_SIZE];
		int len;
		char *pos;

		len = readlink(path, target, sizeof(target));
		if (len > 0) {
			target[len] = '\0';
			pos = strrchr(target, '/');
			if (pos != NULL) {
				pos = &pos[1];
				info(udev_device->udev, "cache '%s' with link value '%s'\n", attr, pos);
				list = list_insert(udev_device->udev, &udev_device->attr_list, attr, pos, 0);
				val = udev_list_get_value(list);
			}
		}
		goto out;
	}

	/* skip directories */
	if (S_ISDIR(statbuf.st_mode))
		goto out;

	/* skip non-readable files */
	if ((statbuf.st_mode & S_IRUSR) == 0)
		goto out;

	/* read attribute value */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		info(udev_device->udev, "attribute '%s' can not be opened\n", path);
		goto out;
	}
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		goto out;
	if (size == sizeof(value))
		goto out;

	/* got a valid value, store it in cache and return it */
	value[size] = '\0';
	util_remove_trailing_chars(value, '\n');
	info(udev_device->udev, "'%s' has attribute value '%s'\n", path, value);
	list = list_insert(udev_device->udev, &udev_device->attr_list, attr, value, 0);
	val = udev_list_get_value(list);
out:
	return val;
}
int device_set_syspath(struct udev_device *udev_device, const char *syspath)
{
	const char *pos;

	udev_device->syspath = strdup(syspath);
	if (udev_device->syspath ==  NULL)
		return -ENOMEM;
	udev_device->devpath = &udev_device->syspath[strlen(udev_get_sys_path(udev_device->udev))];
	pos = strrchr(udev_device->syspath, '/');
	if (pos == NULL)
		return -EINVAL;
	udev_device->sysname = &pos[1];
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
	if (list_insert(udev_device->udev, &udev_device->link_list, devlink, NULL, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int device_add_property(struct udev_device *udev_device, const char *key, const char *value)
{
	if (list_insert(udev_device->udev, &udev_device->properties_list, key, value, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int device_add_property_from_string(struct udev_device *udev_device, const char *property)
{
	char name[UTIL_PATH_SIZE];
	char *val;

	strncpy(name, property, sizeof(name));
	val = strchr(name, '=');
	if (val == NULL)
		return -1;
	val[0] = '\0';
	val = &val[1];
	if (val[0] == '\0')
		val = NULL;
	device_add_property(udev_device, name, val);
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

