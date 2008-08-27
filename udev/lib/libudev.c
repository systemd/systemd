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

void udev_log(struct udev *udev,
	      int priority, const char *file, int line, const char *fn,
	      const char *format, ...)
{
	va_list args;

	va_start(args, format);
	udev->log_fn(udev, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct udev *udev,
		       int priority, const char *file, int line, const char *fn,
		       const char *format, va_list args)
{
	static int log = -1;

	if (log == -1) {
		if (getenv("LIBUDEV_DEBUG") != NULL)
			log = 1;
		else
			log = 0;
	}

	if (log == 1) {
		fprintf(stderr, "libudev: %s: ", fn);
		vfprintf(stderr, format, args);
	}
}

/* glue to udev logging, needed until udev logging code is "fixed" */
#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_stderr(NULL, priority, NULL, 0, "", format, args);
	va_end(args);
}
#endif

static ssize_t get_subsystem(struct udev *udev, const char *devpath, char *subsystem, size_t size)
{
	char path[PATH_SIZE];
	ssize_t len;
	const char *pos;

	strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, devpath, sizeof(path));
	strlcat(path, "/subsystem", sizeof(path));
	len = readlink(path, path, sizeof(path));
	if (len < 0 || len >= (ssize_t) sizeof(path))
		return -1;
	path[len] = '\0';
	pos = strrchr(path, '/');
	if (pos == NULL)
		return -1;
	pos = &pos[1];
	return strlcpy(subsystem, pos, size);
}

/**
 * udev_new:
 *
 * Create udev library context.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the ressources of the udev library context.
 *
 * Returns: a new udev library context
 **/
struct udev *udev_new(void)
{
	struct udev *udev;

	udev = malloc(sizeof(struct udev));
	if (udev == NULL)
		return NULL;
	memset(udev, 0x00, (sizeof(struct udev)));
	udev->refcount = 1;
	udev->log_fn = log_stderr;
	udev_config_init();
	sysfs_init();
	log_info(udev, "context %p created\n", udev);
	return udev;
}

/**
 * udev_ref:
 * @udev: udev library context
 *
 * Take a reference of the udev library context.
 *
 * Returns: the passed udev library context
 **/
struct udev *udev_ref(struct udev *udev)
{
	udev->refcount++;
	return udev;
}

/**
 * udev_unref:
 * @udev: udev library context
 *
 * Drop a reference of the udev library context. If the refcount
 * reaches zero, the ressources of the context will be released.
 *
 **/
void udev_unref(struct udev *udev)
{
	udev->refcount--;
	if (udev->refcount > 0)
		return;
	sysfs_cleanup();
	log_info(udev, "context %p released\n", udev);
	free(udev);
}

/**
 * udev_set_log_fn:
 * @udev: udev library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging, which writes to stderr if the
 * LIBUDEV_DEBUG environment variable is set, can be
 * overridden by a custom function, to plug log messages
 * into the users logging functionality.
 *
 **/
void udev_set_log_fn(struct udev *udev,
		     void (*log_fn)(struct udev *udev,
				    int priority, const char *file, int line, const char *fn,
				    const char *format, va_list args))
{
	udev->log_fn = log_fn;
	log_info(udev, "custom logging function %p registered\n", udev);
}

/**
 * udev_get_sys_path:
 * @udev: udev library context
 *
 * Retrieve the sysfs mount point. The default is "/sys". For
 * testing purposes, it can be overridden with the environment
 * variable SYSFS_PATH.
 *
 * Returns: the sys mount point
 **/
const char *udev_get_sys_path(struct udev *udev)
{
	return sysfs_path;
}

/**
 * udev_get_dev_path:
 * @udev: udev library context
 *
 * Retrieve the device directory path. The default value is "/dev",
 * the actual value may be overridden in the udev configuration
 * file.
 *
 * Returns: the device directory path
 **/
const char *udev_get_dev_path(struct udev *udev)
{
	return udev_root;
}

static struct udev_device *device_init(struct udev *udev)
{
	struct udev_device *udev_device;

	udev_device = malloc(sizeof(struct udev_device));
	if (udev_device == NULL)
		return NULL;
	memset(udev_device, 0x00, sizeof(struct udev_device));
	udev_device->refcount = 1;
	udev_device->udev = udev;
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
	char path[PATH_SIZE];
	struct stat statbuf;
	struct udev_device *udev_device;
	int err;

	strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, devpath, sizeof(path));
	if (stat(path, &statbuf) != 0)
		return NULL;
	if (!S_ISDIR(statbuf.st_mode))
		return NULL;

	udev_device = device_init(udev);
	if (udev_device == NULL)
		return NULL;

	udev_device->udevice = udev_device_init(NULL);
	if (udev_device->udevice == NULL) {
		free(udev_device);
		return NULL;
	}
	log_info(udev, "device %p created\n", udev_device);

	strlcpy(path, devpath, sizeof(path));
	sysfs_resolve_link(path, sizeof(path));

	err = udev_db_get_device(udev_device->udevice, path);
	if (err >= 0)
		log_info(udev, "device %p filled with udev database data\n", udev_device);
	log_info(udev, "device %p filled with %s data\n", udev_device, udev_device_get_devpath(udev_device));
	return udev_device;
}

/**
 * udev_device_get_udev:
 *
 * Retrieve the udev library context the device was created with.
 *
 * Returns: the udev library context
 **/
struct udev *udev_device_get_udev(struct udev_device *udev_device)
{
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
	udev_device->refcount--;
	if (udev_device->refcount > 0)
		return;
	udev_device_cleanup(udev_device->udevice);
	free(udev_device);
}

/**
 * udev_device_get_devpath:
 * @udev_device: udev device
 *
 * Retrieve the sys path of the udev device. The path does not contain
 * the sys mount point.
 *
 * Returns: the sys path of the udev device
 **/
const char *udev_device_get_devpath(struct udev_device *udev_device)
{
	return udev_device->udevice->dev->devpath;
}

/**
 * udev_device_get_devname:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path does not contain the device directory, and does not contain
 * a leading '/'.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
const char *udev_device_get_devname(struct udev_device *udev_device)
{
	if (udev_device->udevice->name[0] == '\0')
		return NULL;
	return udev_device->udevice->name;
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
	struct sysfs_device *dev = udev_device->udevice->dev;
	if (dev->subsystem[0] != '\0')
		return dev->subsystem;
	if (get_subsystem(udev_device->udev, dev->devpath,
			  dev->subsystem, sizeof(dev->subsystem)) < 2)
		return NULL;
	return dev->subsystem;
}

/**
 * udev_device_get_devlinks:
 * @udev_device: udev device
 * @cb: function to be called for every device link found
 * @data: data to be passed to the function
 *
 * Retrieve the device links pointing to the device file of the
 * udev device. For every device link, the passed function will be
 * called with the device link string. If the function returns 1,
 * remaning device links will be ignored. The device link path
 * does not contain the device directory, and does not contain
 * a leading '/'.
 *
 * Returns: the number of device links passed to the caller, or a negative value on error
 **/
int udev_device_get_devlinks(struct udev_device *udev_device,
			      int (*cb)(struct udev_device *udev_device, const char *value, void *data),
			      void *data)
{
	struct name_entry *name_loop;
	int count = 0;

	list_for_each_entry(name_loop, &udev_device->udevice->symlink_list, node) {
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
	struct name_entry *name_loop;
	int count = 0;

	list_for_each_entry(name_loop, &udev_device->udevice->env_list, node) {
		char name[PATH_SIZE];
		char *val;

		strncpy(name, name_loop->name, PATH_SIZE);
		name[PATH_SIZE-1] = '\0';
		val = strchr(name, '=');
		if (val == NULL)
			continue;
		val[0] = '\0';
		val = &val[1];
		if (cb(udev_device, name, val, data) != 0)
			break;
	}
	return count;
}

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
		sysfs_resolve_link(devpath, sizeof(devpath));
		name_list_add(device_list, devpath, 1);
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
			log_info(udev, "delaying: %s\n", devpath);
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

	if (get_subsystem(udev, devpath, subsystem, sizeof(subsystem)) < 2)
		return -1;
	*cb_rc = cb(udev, devpath, subsystem, name, data);
	return 0;
}

/**
 * udev_devices_enumerate:
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
int udev_devices_enumerate(struct udev *udev, const char *subsystem,
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
	strlcpy(base, sysfs_path, sizeof(base));
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
