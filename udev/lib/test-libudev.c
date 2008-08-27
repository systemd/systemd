/*
 * test-libudev
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
#include <stdarg.h>
#include "libudev.h"

static void log_fn(struct udev *udev,
		   int priority, const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	printf("test-libudev: %s %s:%d ", fn, file, line);
	vprintf(format, args);
}

static int devlinks_cb(struct udev_device *udev_device, const char *value, void *data)
{
	printf("link: %s\n", value);
	return 0;
}

static int devices_enum_cb(struct udev *udev,
			   const char *devpath, const char *subsystem, const char *name,
			   void *data)
{
	printf("device: %s (%s) %s\n", devpath, subsystem, name);
	return 0;
}

static int properties_cb(struct udev_device *udev_device, const char *key, const char *value, void *data)
{
	printf("property: %s=%s\n", key, value);
	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	struct udev *udev;
	struct udev_device *device;
	const char *str;
	const char *devpath = "/devices/virtual/mem/null";
	const char *subsystem = NULL;

	if (argv[1] != NULL) {
		devpath = argv[1];
		if (argv[2] != NULL)
			subsystem = argv[2];
	}

	udev = udev_new();
	printf("context: %p\n", udev);
	if (udev == NULL) {
		printf("no context\n");
		return 1;
	}
	udev_set_log_fn(udev, log_fn);
	printf("set log: %p\n", log_fn);

	str = udev_get_sys_path(udev);
	printf("sys_path: %s\n", str);
	str = udev_get_dev_path(udev);
	printf("dev_path: %s\n", str);

	printf("looking at device: %s\n", devpath);
	device = udev_device_new_from_devpath(udev, devpath);
	printf("device: %p\n", device);
	if (device == NULL) {
		printf("no device\n");
		return 1;
	}
	str = udev_device_get_devpath(device);
	printf("devpath: %s\n", str);
	str = udev_device_get_subsystem(device);
	printf("subsystem: %s\n", str);
	str = udev_device_get_devname(device);
	printf("devname: %s\n", str);
	udev_device_get_devlinks(device, devlinks_cb, NULL);
	udev_device_get_properties(device, properties_cb, NULL);
	udev_device_unref(device);

	if (subsystem == NULL)
		printf("enumerating devices from all subsystems\n");
	else
		printf("enumerating devices from subsystem: %s\n", subsystem);
	udev_devices_enumerate(udev, subsystem, devices_enum_cb, NULL);

	udev_unref(udev);
	return 0;
}
