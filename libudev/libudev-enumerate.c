/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "libudev.h"
#include "libudev-private.h"

/**
 * SECTION:libudev-enumerate
 * @short_description: lookup and sort sys devices
 *
 * Lookup devices in the sys filesystem, filter devices by properties,
 * and return a sorted list of devices.
 */

struct syspath {
	char *syspath;
	size_t len;
};

/**
 * udev_enumerate:
 *
 * Opaque object representing one device lookup/sort context.
 */
struct udev_enumerate {
	struct udev *udev;
	int refcount;
	struct udev_list_node sysattr_match_list;
	struct udev_list_node sysattr_nomatch_list;
	struct udev_list_node subsystem_match_list;
	struct udev_list_node subsystem_nomatch_list;
	struct udev_list_node sysname_match_list;
	struct udev_list_node properties_match_list;
	struct udev_list_node devices_list;
	struct syspath *devices;
	unsigned int devices_cur;
	unsigned int devices_max;
	bool devices_uptodate:1;
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
	udev_list_init(&udev_enumerate->sysattr_match_list);
	udev_list_init(&udev_enumerate->sysattr_nomatch_list);
	udev_list_init(&udev_enumerate->subsystem_match_list);
	udev_list_init(&udev_enumerate->subsystem_nomatch_list);
	udev_list_init(&udev_enumerate->sysname_match_list);
	udev_list_init(&udev_enumerate->properties_match_list);
	udev_list_init(&udev_enumerate->devices_list);
	return udev_enumerate;
}

/**
 * udev_enumerate_ref:
 * @udev_enumerate: context
 *
 * Take a reference of a enumeration context.
 *
 * Returns: the passed enumeration context
 **/
struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	udev_enumerate->refcount++;
	return udev_enumerate;
}

/**
 * udev_enumerate_unref:
 * @udev_enumerate: context
 *
 * Drop a reference of an enumeration context. If the refcount reaches zero,
 * all resources of the enumeration context will be released.
 **/
void udev_enumerate_unref(struct udev_enumerate *udev_enumerate)
{
	unsigned int i;

	if (udev_enumerate == NULL)
		return;
	udev_enumerate->refcount--;
	if (udev_enumerate->refcount > 0)
		return;
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->sysattr_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->sysattr_nomatch_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->subsystem_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->subsystem_nomatch_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->sysname_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->properties_match_list);
	udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->devices_list);
	for (i = 0; i < udev_enumerate->devices_cur; i++)
		free(udev_enumerate->devices[i].syspath);
	free(udev_enumerate->devices);
	free(udev_enumerate);
}

/**
 * udev_enumerate_get_udev:
 * @udev_enumerate: context
 *
 * Returns: the udev library context.
 */
struct udev *udev_enumerate_get_udev(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	return udev_enumerate->udev;
}

static int syspath_add(struct udev_enumerate *udev_enumerate, const char *syspath)
{
	char *path;
	struct syspath *entry;

	/* double array size if needed */
	if (udev_enumerate->devices_cur >= udev_enumerate->devices_max) {
		struct syspath *buf;
		unsigned int add;

		add = udev_enumerate->devices_max;
		if (add < 1024)
			add = 1024;
		buf = realloc(udev_enumerate->devices, (udev_enumerate->devices_max + add) * sizeof(struct syspath));
		if (buf == NULL)
			return -ENOMEM;
		udev_enumerate->devices = buf;
		udev_enumerate->devices_max += add;
	}

	path = strdup(syspath);
	if (path == NULL)
		return -ENOMEM;
	entry = &udev_enumerate->devices[udev_enumerate->devices_cur];
	entry->syspath = path;
	entry->len = strlen(path);
	udev_enumerate->devices_cur++;
	udev_enumerate->devices_uptodate = false;
	return 0;
}

static int syspath_cmp(const void *p1, const void *p2)
{
	const struct syspath *path1 = p1;
	const struct syspath *path2 = p2;
	size_t len;
	int ret;

	len = MIN(path1->len, path2->len);
	ret = memcmp(path1->syspath, path2->syspath, len);
	if (ret == 0) {
		if (path1->len < path2->len)
			ret = -1;
		else if (path1->len > path2->len)
			ret = 1;
	}
	return ret;
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

/**
 * udev_enumerate_get_list_entry:
 * @udev_enumerate: context
 *
 * Returns: the first entry of the sorted list of device paths.
 */
struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate)
{
	if (udev_enumerate == NULL)
		return NULL;
	if (!udev_enumerate->devices_uptodate) {
		unsigned int i;
		unsigned int max;
		struct syspath *prev = NULL;

		udev_list_cleanup_entries(udev_enumerate->udev, &udev_enumerate->devices_list);
		qsort(udev_enumerate->devices, udev_enumerate->devices_cur, sizeof(struct syspath), syspath_cmp);

		max = udev_enumerate->devices_cur;
		for (i = 0; i < max; i++) {
			struct syspath *entry = &udev_enumerate->devices[i];

			/* skip duplicated entries */
			if (prev != NULL &&
			    entry->len == prev->len &&
			    memcmp(entry->syspath, prev->syspath, entry->len) == 0)
				continue;
			prev = entry;

			/* skip to be delayed devices, and add them to the end of the list */
			if (devices_delay(udev_enumerate->udev, entry->syspath)) {
				syspath_add(udev_enumerate, entry->syspath);
				continue;
			}

			udev_list_entry_add(udev_enumerate->udev, &udev_enumerate->devices_list,
					    entry->syspath, NULL, 0, 0);
		}
		/* add and cleanup delayed devices from end of list */
		for (i = max; i < udev_enumerate->devices_cur; i++) {
			struct syspath *entry = &udev_enumerate->devices[i];

			udev_list_entry_add(udev_enumerate->udev, &udev_enumerate->devices_list,
					    entry->syspath, NULL, 0, 0);
			free(entry->syspath);
		}
		udev_enumerate->devices_cur = max;

		udev_enumerate->devices_uptodate = true;
	}
	return udev_list_get_entry(&udev_enumerate->devices_list);
}

/**
 * udev_enumerate_add_match_subsystem:
 * @udev_enumerate: context
 * @subsystem: filter for a subsystem of the device to include in the list
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
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

/**
 * udev_enumerate_add_nomatch_subsystem:
 * @udev_enumerate: context
 * @subsystem: filter for a subsystem of the device to exclude from the list
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
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

/**
 * udev_enumerate_add_match_sysattr:
 * @udev_enumerate: context
 * @sysattr: filter for a sys attribute at the device to include in the list
 * @value: optional value of the sys attribute
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_enumerate_add_match_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (sysattr == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
			   &udev_enumerate->sysattr_match_list, sysattr, value, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

/**
 * udev_enumerate_add_nomatch_sysattr:
 * @udev_enumerate: context
 * @sysattr: filter for a sys attribute at the device to exclude from the list
 * @value: optional value of the sys attribute
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_enumerate_add_nomatch_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (sysattr == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
			   &udev_enumerate->sysattr_nomatch_list, sysattr, value, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

static int match_sysattr_value(struct udev *udev, const char *syspath, const char *sysattr, const char *match_val)
{
	struct udev_device *device;
	const char *val = NULL;
	bool match = false;

	device = udev_device_new_from_syspath(udev, syspath);
	if (device == NULL)
		return -EINVAL;
	val = udev_device_get_sysattr_value(device, sysattr);
	if (val == NULL)
		goto exit;
	if (match_val == NULL) {
		match = true;
		goto exit;
	}
	if (fnmatch(match_val, val, 0) == 0) {
		match = true;
		goto exit;
	}
exit:
	udev_device_unref(device);
	return match;
}

/**
 * udev_enumerate_add_match_property:
 * @udev_enumerate: context
 * @property: filter for a property of the device to include in the list
 * @value: value of the property
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_enumerate_add_match_property(struct udev_enumerate *udev_enumerate, const char *property, const char *value)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (property == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
				&udev_enumerate->properties_match_list, property, value, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

/**
 * udev_enumerate_add_match_sysname:
 * @udev_enumerate: context
 * @sysname: filter for the name of the device to include in the list
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_enumerate_add_match_sysname(struct udev_enumerate *udev_enumerate, const char *sysname)
{
	if (udev_enumerate == NULL)
		return -EINVAL;
	if (sysname == NULL)
		return 0;
	if (udev_list_entry_add(udev_enumerate_get_udev(udev_enumerate),
				&udev_enumerate->sysname_match_list, sysname, NULL, 1, 0) == NULL)
		return -ENOMEM;
	return 0;
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

static int match_property(struct udev_enumerate *udev_enumerate, const char *syspath)
{
	struct udev_device *dev;
	struct udev_list_entry *list_entry;
	int match = false;

	/* no match always matches */
	if (udev_list_get_entry(&udev_enumerate->properties_match_list) == NULL)
		return 1;

	/* no device does not match */
	dev = udev_device_new_from_syspath(udev_enumerate->udev, syspath);
	if (dev == NULL)
		return 0;

	/* loop over matches */
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->properties_match_list)) {
		const char *match_key = udev_list_entry_get_name(list_entry);
		const char *match_value = udev_list_entry_get_value(list_entry);
		struct udev_list_entry *property_entry;

		/* loop over device properties */
		udev_list_entry_foreach(property_entry, udev_device_get_properties_list_entry(dev)) {
			const char *dev_key = udev_list_entry_get_name(property_entry);
			const char *dev_value = udev_list_entry_get_value(property_entry);

			if (fnmatch(match_key, dev_key, 0) != 0)
				continue;
			if (match_value == NULL && dev_value == NULL) {
				match = true;
				goto out;
			}
			if (match_value == NULL || dev_value == NULL)
				continue;
			if (fnmatch(match_value, dev_value, 0) == 0) {
				match = true;
				goto out;
			}
		}
	}
out:
	udev_device_unref(dev);
	return match;
}

static int match_sysname(struct udev_enumerate *udev_enumerate, const char *sysname)
{
	struct udev_list_entry *list_entry;

	if (udev_list_get_entry(&udev_enumerate->sysname_match_list) == NULL)
		return 1;

	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_enumerate->sysname_match_list)) {
		if (fnmatch(udev_list_entry_get_name(list_entry), sysname, 0) != 0)
			continue;
		return 1;
	}
	return 0;
}

static int scan_dir_and_add_devices(struct udev_enumerate *udev_enumerate,
				    const char *basedir, const char *subdir1, const char *subdir2)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char path[UTIL_PATH_SIZE];
	size_t l;
	char *s;
	DIR *dir;
	struct dirent *dent;

	s = path;
	l = util_strpcpyl(&s, sizeof(path), udev_get_sys_path(udev), "/", basedir, NULL);
	if (subdir1 != NULL)
		l = util_strpcpyl(&s, l, "/", subdir1, NULL);
	if (subdir2 != NULL)
		l = util_strpcpyl(&s, l, "/", subdir2, NULL);
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char syspath[UTIL_PATH_SIZE];
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;

		if (dent->d_name[0] == '.')
			continue;
		if (!match_sysname(udev_enumerate, dent->d_name))
			continue;

		util_strscpyl(syspath, sizeof(syspath), path, "/", dent->d_name, NULL);
		if (lstat(syspath, &statbuf) != 0)
			continue;
		if (S_ISREG(statbuf.st_mode))
			continue;
		if (S_ISLNK(statbuf.st_mode))
			util_resolve_sys_link(udev, syspath, sizeof(syspath));

		util_strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);
		if (stat(filename, &statbuf) != 0)
			continue;
		if (!match_sysattr(udev_enumerate, syspath))
			continue;
		if (!match_property(udev_enumerate, syspath))
			continue;
		syspath_add(udev_enumerate, syspath);
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

	util_strscpyl(path, sizeof(path), udev_get_sys_path(udev), "/", basedir, NULL);
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

/**
 * udev_enumerate_add_syspath:
 * @udev_enumerate: context
 * @syspath: path of a device
 *
 * Add a device to the list of devices, to retrieve it back sorted in dependency order.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_enumerate_add_syspath(struct udev_enumerate *udev_enumerate, const char *syspath)
{
	struct udev_device *udev_device;

	if (udev_enumerate == NULL)
		return -EINVAL;
	if (syspath == NULL)
		return 0;
	/* resolve to real syspath */
	udev_device = udev_device_new_from_syspath(udev_enumerate->udev, syspath);
	if (udev_device == NULL)
		return -EINVAL;
	syspath_add(udev_enumerate, udev_device_get_syspath(udev_device));
	udev_device_unref(udev_device);
	return 0;
}

/**
 * udev_enumerate_scan_devices:
 * @udev_enumerate: udev enumeration context
 *
 * Returns: 0 on success, otherwise a negative error value.
 **/
int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;

	if (udev_enumerate == NULL)
		return -EINVAL;
	util_strscpyl(base, sizeof(base), udev_get_sys_path(udev), "/subsystem", NULL);
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
		util_strscpyl(base, sizeof(base), udev_get_sys_path(udev), "/class/block", NULL);
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
 * Returns: 0 on success, otherwise a negative error value.
 **/
int udev_enumerate_scan_subsystems(struct udev_enumerate *udev_enumerate)
{
	struct udev *udev = udev_enumerate_get_udev(udev_enumerate);
	char base[UTIL_PATH_SIZE];
	struct stat statbuf;
	const char *subsysdir;

	if (udev_enumerate == NULL)
		return -EINVAL;
	util_strscpyl(base, sizeof(base), udev_get_sys_path(udev), "/subsystem", NULL);
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
