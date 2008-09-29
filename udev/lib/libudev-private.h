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

#include <syslog.h>
#include "libudev.h"

static inline void __attribute__ ((format(printf, 2, 3)))
log_null(struct udev *udev, const char *format, ...)
{
}

#ifdef USE_LOG
#ifdef USE_DEBUG
#define dbg(udev, arg...) \
	udev_log(udev, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, ## arg)
#else
#define dbg log_null
#endif /* USE_DEBUG */

#define info(udev, arg...) \
	udev_log(udev, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, ## arg)

#define err(udev, arg...) \
	udev_log(udev, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, ## arg)
#else
#define dbg log_null
#define info log_null
#define err log_null
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
extern int device_set_syspath(struct udev_device *udev_device, const char *syspath);
extern int device_set_subsystem(struct udev_device *udev_device, const char *subsystem);
extern int device_set_devnode(struct udev_device *udev_device, const char *devnode);
extern int device_add_devlink(struct udev_device *udev_device, const char *devlink);
extern int device_add_property(struct udev_device *udev_device, const char *key, const char *value);
extern int device_add_property_from_string(struct udev_device *udev_device, const char *property);
extern int device_set_action(struct udev_device *udev_device, const char *action);
extern int device_set_driver(struct udev_device *udev_device, const char *driver);
extern const char *device_get_devpath_old(struct udev_device *udev_device);
extern int device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old);
extern const char *device_get_physdevpath(struct udev_device *udev_device);
extern int device_set_physdevpath(struct udev_device *udev_device, const char *physdevpath);
extern int device_get_timeout(struct udev_device *udev_device);
extern int device_set_timeout(struct udev_device *udev_device, int timeout);
extern int device_get_event_timeout(struct udev_device *udev_device);
extern int device_set_event_timeout(struct udev_device *udev_device, int event_timeout);
extern int device_set_devnum(struct udev_device *udev_device, dev_t devnum);
extern int device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum);
extern int device_get_num_fake_partitions(struct udev_device *udev_device);
extern int device_set_num_fake_partitions(struct udev_device *udev_device, int num);
extern int device_get_devlink_priority(struct udev_device *udev_device);
extern int device_set_devlink_priority(struct udev_device *udev_device, int prio);
extern int device_get_ignore_remove(struct udev_device *udev_device);
extern int device_set_ignore_remove(struct udev_device *udev_device, int ignore);
extern void device_set_info_loaded(struct udev_device *device);

/* libudev-ctrl - daemon runtime setup */
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

/* libudev-list */
struct list_node {
	struct list_node *next, *prev;
};
extern void list_init(struct list_node *list);
extern void list_cleanup(struct udev *udev, struct list_node *name_list);
extern struct udev_list_entry *list_entry_add(struct udev *udev, struct list_node *list,
					      const char *name, const char *value,
					      int unique, int sort);
extern void list_entry_remove(struct udev_list_entry *entry);
extern struct udev_list_entry *list_get_entry(struct list_node *list);
extern void list_entry_move_to_end(struct udev_list_entry *list_entry);
#define list_entry_foreach_safe(entry, tmp, first) \
	for (entry = first, \
	     tmp = udev_list_entry_get_next(entry); \
	     entry != NULL; \
	     entry = tmp, tmp = udev_list_entry_get_next(tmp))

/* libudev-utils */
#define UTIL_PATH_SIZE		1024
#define UTIL_LINE_SIZE		2048
#define UTIL_NAME_SIZE		512
extern ssize_t util_get_sys_subsystem(struct udev *udev, const char *syspath, char *subsystem, size_t size);
extern ssize_t util_get_sys_driver(struct udev *udev, const char *syspath, char *driver, size_t size);
extern int util_resolve_sys_link(struct udev *udev, char *syspath, size_t size);
extern int util_log_priority(const char *priority);
extern size_t util_path_encode(char *s, size_t len);
extern size_t util_path_decode(char *s);
extern void util_remove_trailing_chars(char *path, char c);
extern size_t util_strlcpy(char *dst, const char *src, size_t size);
extern size_t util_strlcat(char *dst, const char *src, size_t size);
extern int util_replace_chars(char *str, const char *white);
#endif
