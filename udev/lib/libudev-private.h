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

#include "config.h"

#include <syslog.h>
#include "libudev.h"
#include "../udev.h"

#ifdef USE_LOG
#ifdef USE_DEBUG
#define dbg(udev, arg...) \
	udev_log(udev, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, ## arg)
#else
#define dbg(format, arg...) do { } while (0)
#endif /* USE_DEBUG */

#define info(udev, arg...) \
	udev_log(udev, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, ## arg)

#define err(udev, arg...) \
	udev_log(udev, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, ## arg)
#else
#define dbg(format, arg...) do { } while (0)
#define info(format, arg...) do { } while (0)
#define err(format, arg...) do { } while (0)
#endif

/* libudev */
void udev_log(struct udev *udev,
	      int priority, const char *file, int line, const char *fn,
	      const char *format, ...)
	      __attribute__ ((format(printf, 6, 7)));
extern struct udev_device *device_init(struct udev *udev);
extern const char *udev_get_rules_path(struct udev *udev);
extern int udev_get_run(struct udev *udev);

/* libudev-device */
extern int device_set_devpath(struct udev_device *udev_device, const char *devpath);
extern int device_set_subsystem(struct udev_device *udev_device, const char *subsystem);
extern int device_set_devname(struct udev_device *udev_device, const char *devname);
extern int device_add_devlink(struct udev_device *udev_device, const char *devlink);
extern int device_add_property(struct udev_device *udev_device, const char *property);
extern int device_set_action(struct udev_device *udev_device, const char *action);
extern int device_set_driver(struct udev_device *udev_device, const char *driver);
extern const char *device_get_devpath_old(struct udev_device *udev_device);
extern int device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old);
extern const char *device_get_physdevpath(struct udev_device *udev_device);
extern int device_set_physdevpath(struct udev_device *udev_device, const char *physdevpath);
extern int device_get_timeout(struct udev_device *udev_device);
extern int device_set_timeout(struct udev_device *udev_device, int timeout);
extern int device_set_devnum(struct udev_device *udev_device, dev_t devnum);
extern int device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum);

/* udev_ctrl - daemon runtime setup */
struct udev_ctrl;
extern struct udev_ctrl *udev_ctrl_new_from_socket(struct udev *udev, const char *socket_path);
extern int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
extern struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl);
extern void udev_ctrl_unref(struct udev_ctrl *uctrl);
extern struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl);
extern int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
extern int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority);
extern int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl);
extern int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl);
extern int udev_ctrl_send_reload_rules(struct udev_ctrl *uctrl);
extern int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key);
extern int udev_ctrl_send_set_max_childs(struct udev_ctrl *uctrl, int count);
extern int udev_ctrl_send_set_max_childs_running(struct udev_ctrl *uctrl, int count);
struct udev_ctrl_msg;
extern struct udev_ctrl_msg *udev_ctrl_msg(struct udev_ctrl *uctrl);
extern struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl *uctrl);
extern struct udev_ctrl_msg *udev_ctrl_msg_ref(struct udev_ctrl_msg *ctrl_msg);
extern void udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_reload_rules(struct udev_ctrl_msg *ctrl_msg);
extern const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_set_max_childs(struct udev_ctrl_msg *ctrl_msg);
extern int udev_ctrl_get_set_max_childs_running(struct udev_ctrl_msg *ctrl_msg);

/* libudev-utils */
extern ssize_t util_get_sys_subsystem(struct udev *udev, const char *devpath, char *subsystem, size_t size);
#endif
