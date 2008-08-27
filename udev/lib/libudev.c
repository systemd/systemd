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
