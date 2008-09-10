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
#include "../udev.h"

static int devices_scan_subsystem(struct udev *udev,
				  const char *basedir, const char *subsystem, const char *subdir,
				  struct list_head *device_list)
{
	char path[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;
	size_t len;

	len = strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, basedir, sizeof(path));
	strlcat(path, "/", sizeof(path));
	strlcat(path, subsystem, sizeof(path));
	if (subdir != NULL)
		strlcat(path, subdir, sizeof(path));
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char devpath[PATH_SIZE];

		if (dent->d_name[0] == '.')
			continue;
		strlcpy(devpath, &path[len], sizeof(devpath));
		strlcat(devpath, "/", sizeof(devpath));
		strlcat(devpath, dent->d_name, sizeof(devpath));
		util_resolve_sys_link(udev, devpath, sizeof(devpath));
		name_list_add(udev, device_list, devpath, 1);
	}
	closedir(dir);
	return 0;
}

static int devices_scan_subsystems(struct udev *udev,
				   const char *basedir, const char *subsystem, const char *subdir,
				   struct list_head *device_list)
{
	char path[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	if (subsystem != NULL)
		return devices_scan_subsystem(udev, basedir, subsystem, subdir, device_list);

	strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, basedir, sizeof(path));
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		if (dent->d_name[0] == '.')
			continue;
		devices_scan_subsystem(udev, basedir, dent->d_name, subdir, device_list);
	}
	closedir(dir);
	return 0;
}

static int devices_delay(struct udev *udev, const char *devpath)
{
	static const char *delay_device_list[] = {
		"/block/md",
		"/block/dm-",
		NULL
	};
	int i;

	for (i = 0; delay_device_list[i] != NULL; i++) {
		if (strstr(devpath, delay_device_list[i]) != NULL) {
			info(udev, "delaying: %s\n", devpath);
			return 1;
		}
	}
	return 0;
}

static int devices_call(struct udev *udev, const char *devpath,
			int (*cb)(struct udev *udev,
				  const char *devpath, const char *subsystem, const char *name,
				  void *data),
			void *data,
			int *cb_rc)
{
	char subsystem[NAME_SIZE];
	const char *name;

	name = strrchr(devpath, '/');
	if (name == NULL)
		return -1;
	name++;

	if (util_get_sys_subsystem(udev, devpath, subsystem, sizeof(subsystem)) < 2)
		return -1;
	*cb_rc = cb(udev, devpath, subsystem, name, data);
	return 0;
}

/**
 * udev_enumerate_devices:
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
int udev_enumerate_devices(struct udev *udev, const char *subsystem,
			   int (*cb)(struct udev *udev,
				     const char *devpath, const char *subsystem, const char *name, void *data),
			   void *data)
{
	char base[PATH_SIZE];
	struct stat statbuf;
	struct list_head device_list;
	struct name_entry *loop_device;
	struct name_entry *tmp_device;
	int cb_rc = 0;
	int count = 0;

	INIT_LIST_HEAD(&device_list);

	/* if we have /sys/subsystem/, forget all the old stuff */
	strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0) {
		devices_scan_subsystems(udev, "/subsystem", subsystem, "/devices", &device_list);
	} else {
		devices_scan_subsystems(udev, "/bus", subsystem, "/devices", &device_list);
		devices_scan_subsystems(udev, "/class", subsystem, NULL, &device_list);
	}

	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		if (devices_delay(udev, loop_device->name))
			continue;
		if (cb_rc == 0)
			if (devices_call(udev, loop_device->name, cb, data, &cb_rc) == 0)
				count++;
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* handle remaining delayed devices */
	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		if (cb_rc == 0)
			if (devices_call(udev, loop_device->name, cb, data, &cb_rc) == 0)
				count++;
		list_del(&loop_device->node);
		free(loop_device);
	}

	return count;
}
