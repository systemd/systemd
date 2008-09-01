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

#ifndef _LIBUDEV_PRIVATE_H_
#define _LIBUDEV_PRIVATE_H_

#include "libudev.h"
#include "../udev.h"

#ifdef USE_LOG
#define log_dbg(udev, arg...) \
	udev_log(udev, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, ## arg)

#define log_info(udev, arg...) \
	udev_log(udev, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, ## arg)

#define log_err(udev, arg...) \
	udev_log(udev, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, ## arg)

void udev_log(struct udev *udev,
	      int priority, const char *file, int line, const char *fn,
	      const char *format, ...)
	      __attribute__ ((format(printf, 6, 7)));
#else
#define log_dbg(format, arg...) do { } while (0)
#define log_info(format, arg...) do { } while (0)
#define log_err(format, arg...) do { } while (0)
#endif

/* libudev */
extern struct udev_device *device_init(struct udev *udev);

/* libudev-device */
extern int device_set_devpath(struct udev_device *udev_device, const char *devpath);
extern int device_set_subsystem(struct udev_device *udev_device, const char *subsystem);
extern int device_set_devname(struct udev_device *udev_device, const char *devname);
extern int device_add_devlink(struct udev_device *udev_device, const char *devlink);
extern int device_add_property(struct udev_device *udev_device, const char *property);

/* libudev-utils */
extern ssize_t util_get_sys_subsystem(struct udev *udev, const char *devpath, char *subsystem, size_t size);
#endif
