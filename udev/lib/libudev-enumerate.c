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

struct udev *udev_enumerate_get_udev(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	return udev_enumerate->udev;
}

struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	return list_get_entry(&udev_enumerate->devices_list);
}

static int devices_scan_subsystem(struct udev *udev,
				  const char *basedir, const char *subsystem, const char *subdir,
				  struct list_node *devices_list)
{
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, basedir, sizeof(path));
	if (subsystem != NULL) {
		util_strlcat(path, "/", sizeof(path));
		util_strlcat(path, subsystem, sizeof(path));
	}
	if (subdir != NULL)
		util_strlcat(path, subdir, sizeof(path));
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char syspath[UTIL_PATH_SIZE];
		struct stat statbuf;

		if (dent->d_name[0] == '.')
			continue;
		util_strlcpy(syspath, path, sizeof(syspath));
		util_strlcat(syspath, "/", sizeof(syspath));
		util_strlcat(syspath, dent->d_name, sizeof(syspath));
		if (stat(syspath, &statbuf) != 0)
			continue;
		if (!S_ISDIR(statbuf.st_mode))
			continue;
		util_resolve_sys_link(udev, syspath, sizeof(syspath));
		list_entry_add(udev, devices_list, syspath, NULL, 1, 1);
	}
	closedir(dir);
	return 0;
}

static int devices_scan_subsystems(struct udev *udev,
				   const char *basedir, const char *subdir,
				   struct udev_list_entry *subsystem_include_list,
				   struct udev_list_entry *subsystem_exclude_list,
				   struct list_node *devices_list)
{
	if (subsystem_include_list != NULL) {
		struct udev_list_entry *list_entry;

		/* if list of subsystems to scan is given, just use this list */
		udev_list_entry_foreach(list_entry, subsystem_include_list)
			devices_scan_subsystem(udev, basedir, udev_list_entry_get_name(list_entry), subdir, devices_list);
	} else {
		char path[UTIL_PATH_SIZE];
		DIR *dir;
		struct dirent *dent;

		/* if no list of subsystems to scan is given, scan all, and possible exclude some subsystems */
		util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
		util_strlcat(path, basedir, sizeof(path));
		dir = opendir(path);
		if (dir == NULL)
			return -1;
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			if (dent->d_name[0] == '.')
				continue;
			if (udev_list_entry_get_by_name(subsystem_exclude_list, dent->d_name) != NULL)
					continue;
			devices_scan_subsystem(udev, basedir, dent->d_name, subdir, devices_list);
		}
		closedir(dir);
	}
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

static struct udev_enumerate *enumerate_new(struct udev *udev)
{
	struct udev_enumerate *udev_enumerate;

	udev_enumerate = malloc(sizeof(struct udev_enumerate));
	if (udev_enumerate == NULL)
		return NULL;
	memset(udev_enumerate, 0x00, (sizeof(struct udev_enumerate)));
	udev_enumerate->refcount = 1;
	udev_enumerate->udev = udev;
	list_init(&udev_enumerate->devices_list);
	return udev_enumerate;
}

/**
 * udev_enumerate_new_from_devices:
 * @udev: udev library context
 * @subsystem: the list of names of subsystems to look for devices
 *
 * Returns: an enumeration context
 **/
struct udev_enumerate *udev_enumerate_new_from_devices(struct udev *udev, const char *subsystem, ...)
{
	struct udev_enumerate *udev_enumerate;
	va_list vargs;
	const char *arg;
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;
	struct list_node subsystem_include_list;
	struct list_node subsystem_exclude_list;
	struct udev_list_entry *list_entry;

	if (udev == NULL)
		return NULL;

	udev_enumerate = enumerate_new(udev);
	if (udev_enumerate == NULL)
		return NULL;

	va_start(vargs, subsystem);
	list_init(&subsystem_include_list);
	list_init(&subsystem_exclude_list);
	for (arg = subsystem; arg != NULL; arg = va_arg(vargs, const char *)) {
		if (arg[0] != '!')
			list_entry_add(udev, &subsystem_include_list, arg, NULL, 1, 0);
		else
			list_entry_add(udev, &subsystem_exclude_list, &arg[1], NULL, 1, 0);
	}
	va_end(vargs);

	/* if we have /sys/subsystem/, forget all the old stuff */
	util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	util_strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0) {
		info(udev, "searching '/subsystem/*/devices/*' dir\n");
		devices_scan_subsystems(udev, "/subsystem", "/devices",
					list_get_entry(&subsystem_include_list),
					list_get_entry(&subsystem_exclude_list),
					&udev_enumerate->devices_list);
	} else {
		info(udev, "searching '/bus/*/devices/*' dir\n");
		devices_scan_subsystems(udev, "/bus", "/devices",
					list_get_entry(&subsystem_include_list),
					list_get_entry(&subsystem_exclude_list),
					&udev_enumerate->devices_list);
		info(udev, "searching '/class/*' dir\n");
		devices_scan_subsystems(udev, "/class", NULL,
					list_get_entry(&subsystem_include_list),
					list_get_entry(&subsystem_exclude_list),
					&udev_enumerate->devices_list);
	}

	list_cleanup(udev, &subsystem_include_list);
	list_cleanup(udev, &subsystem_exclude_list);

	/* sort delayed devices to the end of the list */
	udev_list_entry_foreach(list_entry, list_get_entry(&udev_enumerate->devices_list)) {
		if (devices_delay(udev, udev_list_entry_get_name(list_entry)))
			list_entry_move_to_end(list_entry);
	}
	return udev_enumerate;
}

struct udev_enumerate *udev_enumerate_new_from_subsystems(struct udev *udev)
{
	struct udev_enumerate *udev_enumerate;
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;
	const char *subsysdir;

	if (udev == NULL)
		return NULL;

	udev_enumerate = enumerate_new(udev);
	if (udev_enumerate == NULL)
		return NULL;

	util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	util_strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0)
		subsysdir = "/subsystem";
	else
		subsysdir = "/bus";
	info(udev, "searching '%s/*' dir\n", subsysdir);
	devices_scan_subsystem(udev, subsysdir, NULL, NULL, &udev_enumerate->devices_list);
	info(udev, "searching '%s/*/drivers/*' dir\n", subsysdir);
	devices_scan_subsystems(udev, subsysdir, "/drivers",
				NULL, NULL,
				&udev_enumerate->devices_list);
	return udev_enumerate;
}
