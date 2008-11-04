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
#include <fnmatch.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

static int devices_sort(struct udev_enumerate *udev_enumerate);

struct udev_enumerate {
	struct udev *udev;
	int refcount;
	struct udev_list_node sysattr_match_list;
	struct udev_list_node sysattr_nomatch_list;
	struct udev_list_node subsystem_match_list;
	struct udev_list_node subsystem_nomatch_list;
	struct udev_list_node devices_list;
	int devices_sorted;
};

/**
 * udev_enumerate_new:
 * @udev: udev library context
 *
 * Returns: an enumeration context
 **/
struct udev_enumerate *udev_enumerate_new(struct udev *udev)
{
	struct udev_enumerate *udev_enumerate;

	udev_enumerate = calloc(1, sizeof(struct udev_enumerate));
	if (udev_enumerate == NULL)
		return NULL;
	udev_enumerate->refcount = 1;
	udev_enumerate->udev = udev;
	udev_list_init(&udev_enumerate->devices_list);
	udev_list_init(&udev_enumerate->sysattr_match_list);
	udev_list_init(&udev_enumerate->sysattr_nomatch_list);
	udev_list_init(&udev_enumerate->subsystem_match_list);
	udev_list_init(&udev_enumerate->subsystem_nomatch_list);
	return udev_enumerate;
}

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
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->devices_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->sysattr_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->sysattr_nomatch_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->subsystem_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->subsystem_nomatch_list);
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
	if (!udev_enumerate->devices_sorted)
		devices_sort(udev_enumerate);
	return udev_list_get_entry(&udev_enumerate->devices_list);
}

int udev_enumerate_add_match_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (subsystem == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
				&udev_enumerate->subsystem_match_list, subsystem, NULL, 1, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int udev_enumerate_add_nomatch_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (subsystem == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
				&udev_enumerate->subsystem_nomatch_list, subsystem, NULL, 1, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int udev_enumerate_add_match_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (sysattr == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
			   &udev_enumerate->sysattr_match_list, sysattr, value, 1, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int udev_enumerate_add_nomatch_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (sysattr == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
			   &udev_enumerate->sysattr_nomatch_list, sysattr, value, 1, 0) == NULL)
		return -ENOMEM;
	return 0;
}

static int match_sysattr_value(struct udev *udev, const char *syspath, const char *sysattr, const char *match_val)
{
	struct udev_device *device;
	const char *val = NULL;
	int match = 0;

	device = udev_device_new_from_syspath(udev, syspath);
	if (device == NULL)
		return -EINVAL;
	val = udev_device_get_sysattr_value(device, sysattr);
	if (val == NULL)
		goto exit;
	if (match_val == NULL) {
		match = 1;
		goto exit;
	}
	if (fnmatch(match_val, val, 0) == 0) {
		match = 1;
		goto exit;
	}
exit:
	udev_device_unref(device);
	return match;
}

static int match_sysattr(struct udev_enumerate *udev_enumerate, const char *syspath)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	struct udev_list_entry *list_entry;

	/* skip list */
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->sysattr_nomatch_list)) {
		if (match_sysattr_value(udev, syspath,
				     udev_list_entry_get_name(list_entry),
				     udev_list_entry_get_value(list_entry)))
			return 0;
	}
	/* include list */
	if (udev_list_get_entry(&udev_enumerate->sysattr_match_list) != NULL) {
		udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->sysattr_match_list)) {
			/* anything that does not match, will make it FALSE */
			if (!match_sysattr_value(udev, syspath,
					      udev_list_entry_get_name(list_entry),
					      udev_list_entry_get_value(list_entry)))
				return 0;
		}
		return 1;
	}
	return 1;
}

static int scan_dir_and_add_devices(struct udev_enumerate *udev_enumerate,
				    const char *basedir, const char *subdir1, const char *subdir2)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, basedir, sizeof(path));
	if (subdir1 != NULL) {
		util_strlcat(path, "/", sizeof(path));
		util_strlcat(path, subdir1, sizeof(path));
	}
	if (subdir2 != NULL) {
		util_strlcat(path, "/", sizeof(path));
		util_strlcat(path, subdir2, sizeof(path));
	}
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char syspath[UTIL_PATH_SIZE];
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;

		if (dent->d_name[0] == '.')
			continue;
		util_strlcpy(syspath, path, sizeof(syspath));
		util_strlcat(syspath, "/", sizeof(syspath));
		util_strlcat(syspath, dent->d_name, sizeof(syspath));
		if (lstat(syspath, &statbuf) != 0)
			continue;
		if (S_ISREG(statbuf.st_mode))
			continue;
		if (S_ISLNK(statbuf.st_mode))
			util_resolve_sys_link(udev, syspath, sizeof(syspath));
		util_strlcpy(filename, syspath, sizeof(filename));
		util_strlcat(filename, "/uevent", sizeof(filename));
		if (stat(filename, &statbuf) != 0)
			continue;
		if (!match_sysattr(udev_enumerate, syspath))
			continue;
		udev_list_entry_add(udev, &udev_enumerate->devices_list, syspath, NULL, 1, 1);
	}
	closedir(dir);
	return 0;
}

static int match_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem)
{
	struct udev_list_entry *list_entry;

	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->subsystem_nomatch_list)) {
		if (fnmatch(udev_list_entry_get_name(list_entry), subsystem, 0) == 0)
			return 0;
	}
	if (udev_list_get_entry(&udev_enumerate->subsystem_match_list) != NULL) {
		udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->subsystem_match_list)) {
			if (fnmatch(udev_list_entry_get_name(list_entry), subsystem, 0) == 0)
				return 1;
		}
		return 0;
	}
	return 1;
}

static int scan_dir(struct udev_enumerate *udev_enumerate, const char *basedir, const char *subdir, const char *subsystem)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);

	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, basedir, sizeof(path));
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		if (dent->d_name[0] == '.')
			continue;
		if (!match_subsystem(udev_enumerate, subsystem != NULL ? subsystem : dent->d_name))
			continue;
		scan_dir_and_add_devices(udev_enumerate, basedir, dent->d_name, subdir);
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
			dbg(udev, "delaying: %s\n", syspath);
			return 1;
		}
	}
	return 0;
}

/* sort delayed devices to the end of the list */
static int devices_sort(struct udev_enumerate *udev_enumerate)
{
	struct udev_list_entry *entry_loop;
	struct udev_list_entry *entry_tmp;
	struct udev_list_node devices_list;

	udev_list_init(&devices_list);
	/* move delayed to delay list */
	udev_list_entry_foreach_safe(entry_loop, entry_tmp, udev_list_get_entry(&udev_enumerate->devices_list)) {
		if (devices_delay(udev_enumerate->udev, udev_list_entry_get_name(entry_loop))) {
			udev_list_entry_remove(entry_loop);
			udev_list_entry_append(entry_loop, &devices_list);
		}
	}
	/* move delayed back to end of list */
	udev_list_entry_foreach_safe(entry_loop, entry_tmp, udev_list_get_entry(&devices_list)) {
		udev_list_entry_remove(entry_loop);
		udev_list_entry_append(entry_loop, &udev_enumerate->devices_list);
	}
	udev_enumerate->devices_sorted = 1;
	return 0;
}

int udev_enumerate_add_syspath(struct udev_enumerate *udev_enumerate, const char *syspath)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	struct udev_device *udev_device;

	if (udev_enumerate == NULL)
		return -EINVAL;
	if (syspath == NULL)
		return 0;
	/* resolve to real syspath */
	udev_device = udev_device_new_from_syspath(udev_enumerate->udev, syspath);
	if (udev_device == NULL)
		return -EINVAL;
	udev_list_entry_add(udev, &udev_enumerate->devices_list,
			    udev_device_get_syspath(udev_device), NULL, 1, 1);
	udev_device_unref(udev_device);
	return 0;
}

/**
 * udev_enumerate_scan_devices:
 * @udev_enumerate: udev enumeration context
 *
 * Returns: a negative value on error.
 **/
int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;

	if (udev_enumerate == NULL)
		return -EINVAL;
	util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	util_strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0) {
		/* we have /subsystem/, forget all the old stuff */
		dbg(udev, "searching '/subsystem/*/devices/*' dir\n");
		scan_dir(udev_enumerate, "subsystem", "devices", NULL);
	} else {
		dbg(udev, "searching '/bus/*/devices/*' dir\n");
		scan_dir(udev_enumerate, "bus", "devices", NULL);
		dbg(udev, "searching '/class/*' dir\n");
		scan_dir(udev_enumerate, "class", NULL, NULL);
		/* if block isn't a class, scan /block/ */
		util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
		util_strlcat(base, "/class/block", sizeof(base));
		if (stat(base, &statbuf) != 0) {
			if (match_subsystem(udev_enumerate, "block")) {
				dbg(udev, "searching '/block/*' dir\n");
				/* scan disks */
				scan_dir_and_add_devices(udev_enumerate, "block", NULL, NULL);
				/* scan partitions */
				dbg(udev, "searching '/block/*/*' dir\n");
				scan_dir(udev_enumerate, "block", NULL, "block");
			}
		}
	}
	return 0;
}

/**
 * udev_enumerate_scan_subsystems:
 * @udev_enumerate: udev enumeration context
 *
 * Returns: a negative value on error.
 **/
int udev_enumerate_scan_subsystems(struct udev_enumerate *udev_enumerate)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;
	const char *subsysdir;

	if (udev_enumerate == NULL)
		return -EINVAL;
	util_strlcpy(base, udev_get_sys_path(udev), sizeof(base));
	util_strlcat(base, "/subsystem", sizeof(base));
	if (stat(base, &statbuf) == 0)
		subsysdir = "subsystem";
	else
		subsysdir = "bus";
	if (match_subsystem(udev_enumerate, "subsystem")) {
		dbg(udev, "searching '%s/*' dir\n", subsysdir);
		scan_dir_and_add_devices(udev_enumerate, subsysdir, NULL, NULL);
	}
	if (match_subsystem(udev_enumerate, "drivers")) {
		dbg(udev, "searching '%s/*/drivers/*' dir\n", subsysdir);
		scan_dir(udev_enumerate, subsysdir, "drivers", "drivers");
	}
	return 0;
}
