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
#include <ctype.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_device {
	int refcount;
	struct udev *udev;
	struct udev_device *parent_device;
	char *syspath;
	const char *devpath;
	char *sysname;
	const char *sysnum;
	char *devnode;
	char *subsystem;
	struct udev_list_node devlinks_list;
	struct udev_list_node properties_list;
	char *envp[128];
	int envp_uptodate;
	char *driver;
	dev_t devnum;
	char *action;
	int event_timeout;
	char *devpath_old;
	char *physdevpath;
	int timeout;
	unsigned long long int seqnum;
	int num_fake_partitions;
	int devlink_priority;
	int ignore_remove;
	struct udev_list_node attr_list;
	int info_loaded;
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

	devpath_to_db_path(udev_device->udev, udev_device->devpath, filename, sizeof(filename));

	if (lstat(filename, &stats) != 0) {
		info(udev_device->udev, "no db file to read %s: %m\n", filename);
		return -1;
	}
	if ((stats.st_mode & S_IFMT) == S_IFLNK) {
		char target[UTIL_PATH_SIZE];
		char devnode[UTIL_PATH_SIZE];
		int target_len;
		char *next;

		target_len = readlink(filename, target, sizeof(target));
		if (target_len > 0)
			target[target_len] = '\0';
		else {
			info(udev_device->udev, "error reading db link %s: %m\n", filename);
			return -1;
		}

		next = strchr(target, ' ');
		if (next != NULL) {
			next[0] = '\0';
			next = &next[1];
		}
		util_strlcpy(devnode, udev_get_dev_path(udev_device->udev), sizeof(devnode));
		util_strlcat(devnode, "/", sizeof(devnode));
		util_strlcat(devnode, target, sizeof(devnode));
		udev_device_set_devnode(udev_device, devnode);
		while (next != NULL) {
			char devlink[UTIL_PATH_SIZE];
			const char *lnk;

			lnk = next;
			next = strchr(next, ' ');
			if (next != NULL) {
				next[0] = '\0';
				next = &next[1];
			}
			util_strlcpy(devlink, udev_get_dev_path(udev_device->udev), sizeof(devlink));
			util_strlcat(devlink, "/", sizeof(devlink));
			util_strlcat(devlink, lnk, sizeof(devlink));
			udev_device_add_devlink(udev_device, devlink);
		}
		info(udev_device->udev, "device %p filled with db symlink data '%s'\n", udev_device, udev_device->devnode);
		return 0;
	}

	f = fopen(filename, "r");
	if (f == NULL) {
		info(udev_device->udev, "error reading db file %s: %m\n", filename);
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
			util_strlcpy(filename, udev_get_dev_path(udev_device->udev), sizeof(filename));
			util_strlcat(filename, "/", sizeof(filename));
			util_strlcat(filename, val, sizeof(filename));
			udev_device_set_devnode(udev_device, filename);
			break;
		case 'S':
			util_strlcpy(filename, udev_get_dev_path(udev_device->udev), sizeof(filename));
			util_strlcat(filename, "/", sizeof(filename));
			util_strlcat(filename, val, sizeof(filename));
			udev_device_add_devlink(udev_device, filename);
			break;
		case 'L':
			udev_device_set_devlink_priority(udev_device, atoi(val));
			break;
		case 'T':
			udev_device_set_event_timeout(udev_device, atoi(val));
			break;
		case 'A':
			udev_device_set_num_fake_partitions(udev_device, atoi(val));
			break;
		case 'R':
			udev_device_set_ignore_remove(udev_device, atoi(val));
			break;
		case 'E':
			udev_device_add_property_from_string(udev_device, val);
			break;
		}
	}
	fclose(f);

	info(udev_device->udev, "device %p filled with db file data\n", udev_device);
	return 0;
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

		udev_device_add_property_from_string(udev_device, line);
	}

	udev_device->devnum = makedev(maj, min);

	fclose(f);
	return 0;
}

static void device_load_info(struct udev_device *device)
{
	device->info_loaded = 1;
	device_read_uevent_file(device);
	device_read_db(device);
}

void udev_device_set_info_loaded(struct udev_device *device)
{
	device->info_loaded = 1;
}

struct udev_device *device_new(struct udev *udev)
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
	udev_list_init(&udev_device->devlinks_list);
	udev_list_init(&udev_device->properties_list);
	udev_list_init(&udev_device->attr_list);
	udev_device->event_timeout = -1;
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
	size_t len;
	const char *subdir;
	char path[UTIL_PATH_SIZE];
	char *pos;
	struct stat statbuf;
	struct udev_device *udev_device;

	if (udev == NULL)
		return NULL;
	if (syspath == NULL)
		return NULL;

	/* path starts in sys */
	len = strlen(udev_get_sys_path(udev));
	if (strncmp(syspath, udev_get_sys_path(udev), len) != 0) {
		info(udev, "not in sys :%s\n", syspath);
		return NULL;
	}

	/* path is not a root directory */
	subdir = &syspath[len+1];
	pos = strrchr(subdir, '/');
	if (pos == NULL || pos < &subdir[2]) {
		info(udev, "not a subdir :%s\n", syspath);
		return NULL;
	}

	/* resolve possible symlink to real path */
	util_strlcpy(path, syspath, sizeof(path));
	util_resolve_sys_link(udev, path, sizeof(path));

	/* try to resolve the silly block layout if needed */
	if (strncmp(&path[len], "/block/", 7) == 0) {
		char block[UTIL_PATH_SIZE];
		char part[UTIL_PATH_SIZE];

		util_strlcpy(block, path, sizeof(block));
		pos = strrchr(block, '/');
		if (pos == NULL)
			return NULL;
		util_strlcpy(part, pos, sizeof(part));
		pos[0] = '\0';
		if (util_resolve_sys_link(udev, block, sizeof(block)) == 0) {
			util_strlcpy(path, block, sizeof(path));
			util_strlcat(path, part, sizeof(path));
		}
	}

	/* path exists in sys */
	if (strncmp(&syspath[len], "/devices/", 9) == 0 ||
	    strncmp(&syspath[len], "/class/", 7) == 0 ||
	    strncmp(&syspath[len], "/block/", 7) == 0) {
		char file[UTIL_PATH_SIZE];

		/* all "devices" require a "uevent" file */
		util_strlcpy(file, path, sizeof(file));
		util_strlcat(file, "/uevent", sizeof(file));
		if (stat(file, &statbuf) != 0) {
			info(udev, "not a device: %s\n", syspath);
			return NULL;
		}
	} else {
		/* everything else just needs to be a directory */
		if (stat(path, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode)) {
			info(udev, "directory not found: %s\n", syspath);
			return NULL;
		}
	}

	udev_device = device_new(udev);
	if (udev_device == NULL)
		return NULL;

	udev_device_set_syspath(udev_device, path);
	info(udev, "device %p has devpath '%s'\n", udev_device, udev_device_get_devpath(udev_device));

	return udev_device;
}

struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum)
{
	char path[UTIL_PATH_SIZE];
	const char *type_str;
	struct udev_enumerate *udev_enumerate;
	struct udev_list_entry *list_entry;
	struct udev_device *device = NULL;

	if (type == 'b')
		type_str = "block";
	else if (type == 'c')
		type_str = "char";
	else
		return NULL;

	/* /sys/dev/{block,char}/<maj>:<min> link */
	snprintf(path, sizeof(path), "%s/dev/%s/%u:%u", udev_get_sys_path(udev),
		 type_str, major(devnum), minor(devnum));
	if (util_resolve_sys_link(udev, path, sizeof(path)) == 0)
		return udev_device_new_from_syspath(udev, path);

	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return NULL;

	/* fallback to search sys devices for the major/minor */
	if (type == 'b')
		udev_enumerate_add_match_subsystem(udev_enumerate, "block");
	else if (type == 'c')
		udev_enumerate_add_nomatch_subsystem(udev_enumerate, "block");
	udev_enumerate_scan_devices(udev_enumerate);
	udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(udev_enumerate)) {
		struct udev_device *device_loop;

		device_loop = udev_device_new_from_syspath(udev, udev_list_entry_get_name(list_entry));
		if (device_loop != NULL) {
			if (udev_device_get_devnum(device_loop) == devnum) {
				if (type == 'b' && strcmp(udev_device_get_subsystem(device_loop), "block") != 0)
					continue;
				if (type == 'c' && strcmp(udev_device_get_subsystem(device_loop), "block") == 0)
					continue;
				device = device_loop;
				break;
			}
			udev_device_unref(device_loop);
		}
	}
	udev_enumerate_unref(udev_enumerate);
	return device;
}

struct udev_device *udev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname)
{
	size_t sys_path_len;
	char path_full[UTIL_PATH_SIZE];
	char *path;
	struct stat statbuf;

	sys_path_len = util_strlcpy(path_full, udev_get_sys_path(udev), sizeof(path_full));
	path = &path_full[sys_path_len];

	if (strcmp(subsystem, "subsystem") == 0) {
		util_strlcpy(path, "/subsystem/", sizeof(path_full) - sys_path_len);
		util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;

		util_strlcpy(path, "/bus/", sizeof(path_full) - sys_path_len);
		util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;

		util_strlcpy(path, "/class/", sizeof(path_full) - sys_path_len);
		util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;
		goto out;
	}

	if (strcmp(subsystem, "module") == 0) {
		util_strlcpy(path, "/module/", sizeof(path_full) - sys_path_len);
		util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;
		goto out;
	}

	if (strcmp(subsystem, "drivers") == 0) {
		char subsys[UTIL_NAME_SIZE];
		char *driver;

		util_strlcpy(subsys, sysname, sizeof(subsys));
		driver = strchr(subsys, ':');
		if (driver != NULL) {
			driver[0] = '\0';
			driver = &driver[1];
			util_strlcpy(path, "/subsystem/", sizeof(path_full) - sys_path_len);
			util_strlcat(path, subsys, sizeof(path_full) - sys_path_len);
			util_strlcat(path, "/drivers/", sizeof(path_full) - sys_path_len);
			util_strlcat(path, driver, sizeof(path_full) - sys_path_len);
			if (stat(path_full, &statbuf) == 0)
				goto found;

			util_strlcpy(path, "/bus/", sizeof(path_full) - sys_path_len);
			util_strlcat(path, subsys, sizeof(path_full) - sys_path_len);
			util_strlcat(path, "/drivers/", sizeof(path_full) - sys_path_len);
			util_strlcat(path, driver, sizeof(path_full) - sys_path_len);
			if (stat(path_full, &statbuf) == 0)
				goto found;
		}
		goto out;
	}

	util_strlcpy(path, "/subsystem/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, subsystem, sizeof(path_full) - sys_path_len);
	util_strlcat(path, "/devices/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

	util_strlcpy(path, "/bus/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, subsystem, sizeof(path_full) - sys_path_len);
	util_strlcat(path, "/devices/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

	util_strlcpy(path, "/class/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, subsystem, sizeof(path_full) - sys_path_len);
	util_strlcat(path, "/", sizeof(path_full) - sys_path_len);
	util_strlcat(path, sysname, sizeof(path_full) - sys_path_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;
out:
	return NULL;
found:
	return udev_device_new_from_syspath(udev, path_full);
}

static struct udev_device *device_new_from_parent(struct udev_device *udev_device)
{
	struct udev_device *udev_device_parent = NULL;
	char path[UTIL_PATH_SIZE];
	const char *subdir;

	/* follow "device" link in deprecated sys layout */
	if (strncmp(udev_device->devpath, "/class/", 7) == 0 ||
	    strncmp(udev_device->devpath, "/block/", 7) == 0) {
		util_strlcpy(path, udev_device->syspath, sizeof(path));
		util_strlcat(path, "/device", sizeof(path));
		if (util_resolve_sys_link(udev_device->udev, path, sizeof(path)) == 0)
			udev_device_parent = udev_device_new_from_syspath(udev_device->udev, path);
		return udev_device_parent;
	}

	util_strlcpy(path, udev_device->syspath, sizeof(path));
	subdir = &path[strlen(udev_get_sys_path(udev_device->udev))+1];
	while (1) {
		char *pos;

		pos = strrchr(subdir, '/');
		if (pos == NULL || pos < &subdir[2])
			break;
		pos[0] = '\0';
		udev_device_parent = udev_device_new_from_syspath(udev_device->udev, path);
		if (udev_device_parent != NULL)
			return udev_device_parent;
	}
	return NULL;
}

struct udev_device *udev_device_get_parent(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;

	if (udev_device->parent_device != NULL) {
		info(udev_device->udev, "returning existing parent %p\n", udev_device->parent_device);
		return udev_device->parent_device;
	}
	udev_device->parent_device = device_new_from_parent(udev_device);
	return udev_device->parent_device;
}

struct udev_device *udev_device_get_parent_with_subsystem(struct udev_device *udev_device, const char *subsystem)
{
	struct udev_device *parent;

	parent = udev_device_get_parent(udev_device);
	while (parent != NULL) {
		const char *parent_subsystem;

		parent_subsystem = udev_device_get_subsystem(parent);
		if (parent_subsystem != NULL && strcmp(parent_subsystem, subsystem) == 0)
			break;
		parent = udev_device_get_parent(parent);
	}
	return parent;
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
	unsigned int i;

	if (udev_device == NULL)
		return;
	udev_device->refcount--;
	if (udev_device->refcount > 0)
		return;
	if (udev_device->parent_device != NULL)
		udev_device_unref(udev_device->parent_device);
	free(udev_device->syspath);
	free(udev_device->sysname);
	free(udev_device->devnode);
	free(udev_device->subsystem);
	udev_list_cleanup(udev_device->udev, &udev_device->devlinks_list);
	udev_list_cleanup(udev_device->udev, &udev_device->properties_list);
	free(udev_device->action);
	free(udev_device->driver);
	free(udev_device->devpath_old);
	free(udev_device->physdevpath);
	udev_list_cleanup(udev_device->udev, &udev_device->attr_list);
	for (i = 0; i < ARRAY_SIZE(udev_device->envp) && udev_device->envp[i] != NULL; i++)
		free(udev_device->envp[i]);
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

const char *udev_device_get_sysnum(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	return udev_device->sysnum;
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
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_device->devnode;
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
 * udev_device_get_devlinks_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of device links pointing to the device file of
 * the udev device. The next list entry can be retrieved with
 * udev_list_entry_next(), which returns #NULL if no more entries exist.
 * The devlink path can be retrieved from the list entry by
 * udev_list_entry_get_name(). The path is an absolute path, and starts with
 * the device directory.
 *
 * Returns: the first entry of the device node link list
 **/
struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_list_get_entry(&udev_device->devlinks_list);
}

void udev_device_cleanup_devlinks_list(struct udev_device *udev_device)
{
	udev_list_cleanup(udev_device->udev, &udev_device->devlinks_list);
}

/**
 * udev_device_get_properties_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of key/value device properties of the udev
 * device. The next list entry can be retrieved with udev_list_entry_next(),
 * which returns #NULL if no more entries exist. The property name
 * can be retrieved from the list entry by udev_list_get_name(),
 * the property value by udev_list_get_value().
 *
 * Returns: the first entry of the property list
 **/
struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *udev_device)
{
	if (udev_device == NULL)
		return NULL;
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_list_get_entry(&udev_device->properties_list);
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
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
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
	struct udev_list_entry *list_entry;
	char path[UTIL_PATH_SIZE];
	char value[UTIL_NAME_SIZE];
	struct stat statbuf;
	int fd;
	ssize_t size;
	const char *val = NULL;

	if (udev_device == NULL)
		return NULL;
	if (attr == NULL)
		return NULL;

	/* look for possibly already cached result */
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_device->attr_list)) {
		if (strcmp(udev_list_entry_get_name(list_entry), attr) == 0) {
			info(udev_device->udev, "got '%s' (%s) from cache\n",
			     attr, udev_list_entry_get_value(list_entry));
			return udev_list_entry_get_value(list_entry);
		}
	}

	util_strlcpy(path, udev_device_get_syspath(udev_device), sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, attr, sizeof(path));

	if (lstat(path, &statbuf) != 0) {
		info(udev_device->udev, "stat '%s' failed: %m\n", path);
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
				list_entry = udev_list_entry_add(udev_device->udev, &udev_device->attr_list, attr, pos, 0, 0);
				val = udev_list_entry_get_value(list_entry);
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
	list_entry = udev_list_entry_add(udev_device->udev, &udev_device->attr_list, attr, value, 0, 0);
	val = udev_list_entry_get_value(list_entry);
out:
	return val;
}

int udev_device_set_syspath(struct udev_device *udev_device, const char *syspath)
{
	const char *pos;
	size_t len;

	free(udev_device->syspath);
	udev_device->syspath = strdup(syspath);
	if (udev_device->syspath ==  NULL)
		return -ENOMEM;
	udev_device->devpath = &udev_device->syspath[strlen(udev_get_sys_path(udev_device->udev))];
	udev_device_add_property(udev_device, "DEVPATH", udev_device->devpath);

	pos = strrchr(udev_device->syspath, '/');
	if (pos == NULL)
		return -EINVAL;
	udev_device->sysname = strdup(&pos[1]);
	if (udev_device->sysname == NULL)
		return -ENOMEM;

	/* some devices have '!' in their name, change that to '/' */
	len = 0;
	while (udev_device->sysname[len] != '\0') {
		if (udev_device->sysname[len] == '!')
			udev_device->sysname[len] = '/';
		len++;
	}

	/* trailing number */
	while (isdigit(udev_device->sysname[--len]))
		udev_device->sysnum = &udev_device->sysname[len];
	return 0;
}

int udev_device_set_subsystem(struct udev_device *udev_device, const char *subsystem)
{
	free(udev_device->subsystem);
	udev_device->subsystem = strdup(subsystem);
	if (udev_device->subsystem == NULL)
		return -ENOMEM;
	udev_device_add_property(udev_device, "SUBSYSTEM", udev_device->subsystem);
	return 0;
}

int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode)
{
	free(udev_device->devnode);
	udev_device->devnode = strdup(devnode);
	if (udev_device->devnode == NULL)
		return -ENOMEM;
	udev_device_add_property(udev_device, "DEVNAME", udev_device->devnode);
	return 0;
}

int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink)
{
	char symlinks[UTIL_PATH_SIZE];
	struct udev_list_entry *list_entry;

	if (udev_list_entry_add(udev_device->udev, &udev_device->devlinks_list, devlink, NULL, 1, 0) == NULL)
		return -ENOMEM;
	list_entry =  udev_device_get_devlinks_list_entry(udev_device);
	util_strlcpy(symlinks, udev_list_entry_get_name(list_entry), sizeof(symlinks));
	udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry)) {
		util_strlcat(symlinks, " ", sizeof(symlinks));
		util_strlcat(symlinks, udev_list_entry_get_name(list_entry), sizeof(symlinks));
	}
	udev_device_add_property(udev_device, "DEVLINKS", symlinks);
	return 0;
}

struct udev_list_entry *udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value)
{
	udev_device->envp_uptodate = 0;
	return udev_list_entry_add(udev_device->udev, &udev_device->properties_list, key, value, 1, 0);
}

struct udev_list_entry *udev_device_add_property_from_string(struct udev_device *udev_device, const char *property)
{
	char name[UTIL_PATH_SIZE];
	char *val;

	strncpy(name, property, sizeof(name));
	val = strchr(name, '=');
	if (val == NULL)
		return NULL;
	val[0] = '\0';
	val = &val[1];
	if (val[0] == '\0')
		val = NULL;
	return udev_device_add_property(udev_device, name, val);
}

char **udev_device_get_properties_envp(struct udev_device *udev_device)
{
	if (!udev_device->envp_uptodate) {
		unsigned int i;
		struct udev_list_entry *list_entry;

		for (i = 0; i < ARRAY_SIZE(udev_device->envp) && udev_device->envp[i] != NULL; i++)
			free(udev_device->envp[i]);
		i = 0;
		udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
			asprintf(&udev_device->envp[i++], "%s=%s",
				 udev_list_entry_get_name(list_entry),
				 udev_list_entry_get_value(list_entry));
			if (i+1 >= ARRAY_SIZE(udev_device->envp))
				break;
		}
		udev_device->envp[i] = NULL;
		info(udev_device->udev, "constructed envp from %u properties\n", i);
		udev_device->envp_uptodate = 1;
	}
	return udev_device->envp;
}

int udev_device_set_action(struct udev_device *udev_device, const char *action)
{
	free(udev_device->action);
	udev_device->action = strdup(action);
	if (udev_device->action == NULL)
		return -ENOMEM;
	udev_device_add_property(udev_device, "ACTION", action);
	return 0;
}

int udev_device_set_driver(struct udev_device *udev_device, const char *driver)
{
	free(udev_device->driver);
	udev_device->driver = strdup(driver);
	if (udev_device->driver == NULL)
		return -ENOMEM;
	return 0;
}

const char *udev_device_get_devpath_old(struct udev_device *udev_device)
{
	return udev_device->devpath_old;
}

int udev_device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old)
{
	udev_device->devpath_old = strdup(devpath_old);
	if (udev_device->devpath_old == NULL)
		return -ENOMEM;
	return 0;
}

const char *udev_device_get_physdevpath(struct udev_device *udev_device)
{
	return udev_device->physdevpath;
}

int udev_device_set_physdevpath(struct udev_device *udev_device, const char *physdevpath)
{
	udev_device->physdevpath = strdup(physdevpath);
	if (udev_device->physdevpath == NULL)
		return -ENOMEM;
	return 0;
}

int udev_device_get_timeout(struct udev_device *udev_device)
{
	return udev_device->timeout;
}

int udev_device_set_timeout(struct udev_device *udev_device, int timeout)
{
	udev_device->timeout = timeout;
	return 0;
}
int udev_device_get_event_timeout(struct udev_device *udev_device)
{
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_device->event_timeout;
}

int udev_device_set_event_timeout(struct udev_device *udev_device, int event_timeout)
{
	udev_device->event_timeout = event_timeout;
	return 0;
}

int udev_device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum)
{
	udev_device->seqnum = seqnum;
	return 0;
}

int udev_device_set_devnum(struct udev_device *udev_device, dev_t devnum)
{
	udev_device->devnum = devnum;
	return 0;
}

int udev_device_get_num_fake_partitions(struct udev_device *udev_device)
{
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_device->num_fake_partitions;
}

int udev_device_set_num_fake_partitions(struct udev_device *udev_device, int num)
{
	udev_device->num_fake_partitions = num;
	return 0;
}

int udev_device_get_devlink_priority(struct udev_device *udev_device)
{
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_device->devlink_priority;
}

int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio)
{
	 udev_device->devlink_priority = prio;
	return 0;
}

int udev_device_get_ignore_remove(struct udev_device *udev_device)
{
	if (!udev_device->info_loaded)
		device_load_info(udev_device);
	return udev_device->ignore_remove;
}

int udev_device_set_ignore_remove(struct udev_device *udev_device, int ignore)
{
	udev_device->ignore_remove = ignore;
	return 0;
}
