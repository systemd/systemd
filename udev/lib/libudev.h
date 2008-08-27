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

#ifndef _LIBUDEV_H_
#define _LIBUDEV_H_

struct udev;
struct udev_device;

extern struct udev *udev_new(void);
extern struct udev *udev_ref(struct udev *udev);
extern void udev_unref(struct udev *udev);
extern void udev_set_log_fn(struct udev *udev,
			    void (*log_fn)(struct udev *udev,
					   int priority, const char *file, int line, const char *fn,
					   const char *format, va_list args));
extern const char *udev_get_sys_path(struct udev *udev);
extern const char *udev_get_dev_path(struct udev *udev);

extern struct udev_device *udev_device_new_from_devpath(struct udev *udev, const char *devpath);
extern struct udev_device *udev_device_ref(struct udev_device *udev_device);
extern void udev_device_unref(struct udev_device *udev_device);
extern struct udev *udev_device_get_udev(struct udev_device *udev_device);
extern const char *udev_device_get_devpath(struct udev_device *udev_device);
extern const char *udev_device_get_devname(struct udev_device *udev_device);
extern const char *udev_device_get_subsystem(struct udev_device *udev_device);
extern int udev_device_get_devlinks(struct udev_device *udev_device,
				    int (*cb)(struct udev_device *udev_device,
					      const char *value, void *data),
				    void *data);
extern int udev_device_get_properties(struct udev_device *udev_device,
				      int (*cb)(struct udev_device *udev_device,
						const char *key, const char *value, void *data),
				      void *data);

extern int udev_devices_enumerate(struct udev *udev, const char *subsystem,
				  int (*cb)(struct udev *udev,
					    const char *devpath, const char *subsystem, const char *name, void *data),
				  void *data);

#endif
