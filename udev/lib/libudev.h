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

#include <stdarg.h>
#include <sys/stat.h>

/* this will stay as long as the DeviceKit integration of udev is work in progress */
#if !defined _LIBUDEV_COMPILATION && !defined LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE
#error "#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE is needed to use this experimental library version"
#endif

struct udev;
struct udev_list;
struct udev_device;
struct udev_enumerate;
struct udev_monitor;

/* library context */
extern struct udev *udev_new(void);
extern struct udev *udev_ref(struct udev *udev);
extern void udev_unref(struct udev *udev);
extern void udev_set_log_fn(struct udev *udev,
			    void (*log_fn)(struct udev *udev,
					   int priority, const char *file, int line, const char *fn,
					   const char *format, va_list args));
extern int udev_get_log_priority(struct udev *udev);
extern void udev_set_log_priority(struct udev *udev, int priority);
extern const char *udev_get_sys_path(struct udev *udev);
extern const char *udev_get_dev_path(struct udev *udev);
extern void *udev_get_userdata(struct udev *udev);
extern void udev_set_userdata(struct udev *udev, void *userdata);

/* selinux glue */
extern void udev_selinux_resetfscreatecon(struct udev *udev);
extern void udev_selinux_setfscreatecon(struct udev *udev, const char *file, unsigned int mode);
extern void udev_selinux_lsetfilecon(struct udev *udev, const char *file, unsigned int mode);

/* list iteration */
extern struct udev_list *udev_list_entry_get_next(struct udev_list *list_entry);
extern const char *udev_list_entry_get_name(struct udev_list *list_entry);
extern const char *udev_list_entry_get_value(struct udev_list *list_entry);

/* sys devices */
extern struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath);
extern struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum);
extern struct udev_device *udev_device_get_parent(struct udev_device *udev_device);
extern struct udev_device *udev_device_ref(struct udev_device *udev_device);
extern void udev_device_unref(struct udev_device *udev_device);
extern struct udev *udev_device_get_udev(struct udev_device *udev_device);
extern const char *udev_device_get_devpath(struct udev_device *udev_device);
extern const char *udev_device_get_subsystem(struct udev_device *udev_device);
extern const char *udev_device_get_syspath(struct udev_device *udev_device);
extern const char *udev_device_get_sysname(struct udev_device *udev_device);
extern const char *udev_device_get_devnode(struct udev_device *udev_device);
extern struct udev_list *udev_device_get_devlinks_list(struct udev_device *udev_device);
extern struct udev_list *udev_device_get_properties_list(struct udev_device *udev_device);
extern const char *udev_device_get_driver(struct udev_device *udev_device);
extern dev_t udev_device_get_devnum(struct udev_device *udev_device);
extern const char *udev_device_get_action(struct udev_device *udev_device);
extern unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device);
extern const char *udev_device_get_attr_value(struct udev_device *udev_device, const char *attr);

/* sys enumeration */
extern struct udev_enumerate *udev_enumerate_new_from_subsystems(struct udev *udev, const char *subsystem);
extern struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *udev_enumerate);
extern void udev_enumerate_unref(struct udev_enumerate *udev_enumerate);
extern struct udev_list *udev_enumerate_get_list(struct udev_enumerate *udev_enumerate);

/* udev and kernel device events */
extern struct udev_monitor *udev_monitor_new_from_socket(struct udev *udev, const char *socket_path);
extern struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev);
extern int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor);
extern struct udev_monitor *udev_monitor_ref(struct udev_monitor *udev_monitor);
extern void udev_monitor_unref(struct udev_monitor *udev_monitor);
extern struct udev *udev_monitor_get_udev(struct udev_monitor *udev_monitor);
extern int udev_monitor_get_fd(struct udev_monitor *udev_monitor);
extern struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor);

#endif
