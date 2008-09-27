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
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_enumerate {
	struct udev *udev;
	int refcount;
	struct list_node devices_list;
};

struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	udev_enumerate->refcount++;
	return udev_enumerate;
}

void udev_enumerate_unref(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return;
	udev_enumerate->refcount--;
	if (udev_enumerate->refcount > 0)
		return;
	list_cleanup(udev_enumerate->udev, &udev_enumerate->devices_list);
	free(udev_enumerate);
}

struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	return list_get_entry(&udev_enumerate->devices_list);
}

static int devices_scan_subsystem(struct udev *udev,
				  const char *basedir, const char *subsystem, const char *subdir,
				  struct list_node *device_list)
{
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, basedir, sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, subsystem, sizeof(path));
	if (subdir != NULL)
		util_strlcat(path, subdir, sizeof(path));
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char syspath[UTIL_PATH_SIZE];

		if (dent->d_name[0] == '.')
			continue;
		util_strlcpy(syspath, path, sizeof(syspath));
		util_strlcat(syspath, "/", sizeof(syspath));
		util_strlcat(syspath, dent->d_name, sizeof(syspath));
		util_resolve_sys_link(udev, syspath, sizeof(syspath));
		list_entry_add(udev, device_list, syspath, NULL, 1, 1);
	}
	closedir(dir);
	return 0;
}

static int devices_scan_subsystems(struct udev *udev,
				   const char *basedir, const char *subsystem, const char *subdir,
				   struct list_node *device_list)
{
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	if (subsystem != NULL)
		return devices_scan_subsystem(udev, basedir, subsystem, subdir, device_list);

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, basedir, sizeof(path));
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

static int devices_delay(struct udev *udev, const char *syspath)
{
	static const char *delay_device_list[] = {
		"/block/md",
		"/block/dm-",
		NULL
	};
	size_t len;
	int i;

	len = strlen(udev_get_sys_path(udev));

	for (i = 0; delay_device_list[i] != NULL; i++) {
		if (strstr(&syspath[len], delay_device_list[i]) != NULL) {
			info(udev, "delaying: %s\n", syspath);
			return 1;
		}
	}
	return 0;
}

/**
 * udev_enumerate_new_from_subsystems:
 * @udev: udev library context
 * @subsystem: the subsystem to enumerate
 *
 * Returns: an enumeration context
 **/
struct udev_enumerate *udev_enumerate_new_from_subsystems(struct udev *udev, const char *subsystem)
{
	struct udev_enumerate *udev_enumerate;
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;
	struct udev_list_entry *list_entry;

	if (udev == NULL)
		return NULL;

	udev_enumerate = malloc(sizeof(struct udev_enumerate));
	if (udev_enumerate == NULL)
		return NULL;
	memset(udev_enumerate, 0x00, (sizeof(struct udev_enumerate)));
	udev_enumerate->refcount = 1;
	udev_enumerate->udev = udev;
	list_init(&udev_enumerate->devices_list);

	/* if we have /sys/subsystem/, forget all the old stuff */
	util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	util_strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0) {
		info(udev, "searching 'subsystem/*/devices/*' dir\n");
		devices_scan_subsystems(udev, "/subsystem", subsystem, "/devices", &udev_enumerate->devices_list);
	} else {
		info(udev, "searching 'bus/*/devices/*' dir\n");
		devices_scan_subsystems(udev, "/bus", subsystem, "/devices", &udev_enumerate->devices_list);
		info(udev, "searching 'class/*' dir\n");
		devices_scan_subsystems(udev, "/class", subsystem, NULL, &udev_enumerate->devices_list);
	}

	/* sort delayed devices to the end of the list */
	udev_list_entry_foreach(list_entry, list_get_entry(&udev_enumerate->devices_list)) {
		if (devices_delay(udev, udev_list_entry_get_name(list_entry)))
			list_entry_move_to_end(list_entry);
	}
	return udev_enumerate;
}
