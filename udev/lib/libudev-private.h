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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static inline void __attribute__ ((format(printf, 2, 3)))
udev_log_null(struct udev *udev, const char *format, ...) {}

#ifdef USE_LOG
#  ifdef DEBUG
#    define dbg(udev, arg...) udev_log(udev, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, ## arg)
#  else
#    define dbg(udev, arg...) udev_log_null(udev, ## arg)
#  endif
#  define info(udev, arg...) udev_log(udev, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, ## arg)
#  define err(udev, arg...) udev_log(udev, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, ## arg)
#else
#  define dbg(udev, arg...) udev_log_null(udev, ## arg)
#  define info(udev, arg...) udev_log_null(udev, ## arg)
#  define err(udev, arg...) udev_log_null(udev, ## arg)
#endif

/* libudev */
void udev_log(struct udev *udev,
	      int priority, const char *file, int line, const char *fn,
	      const char *format, ...)
	      __attribute__ ((format(printf, 6, 7)));
extern struct udev_device *device_new(struct udev *udev);
extern const char *udev_get_rules_path(struct udev *udev);
extern int udev_get_run(struct udev *udev);
extern struct udev_list_entry *udev_add_property(struct udev *udev, const char *key, const char *value);
extern struct udev_list_entry *udev_get_properties_list_entry(struct udev *udev);

/* libudev-device */
extern int udev_device_set_syspath(struct udev_device *udev_device, const char *syspath);
extern int udev_device_set_subsystem(struct udev_device *udev_device, const char *subsystem);
extern int udev_device_set_devtype(struct udev_device *udev_device, const char *devtype);
extern int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode);
extern int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink);
extern void udev_device_cleanup_devlinks_list(struct udev_device *udev_device);
extern struct udev_list_entry *udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value);
extern struct udev_list_entry *udev_device_add_property_from_string(struct udev_device *udev_device, const char *property);
extern char **udev_device_get_properties_envp(struct udev_device *udev_device);
extern ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf);
extern int udev_device_read_db(struct udev_device *udev_device);
extern int udev_device_read_uevent_file(struct udev_device *udev_device);
extern int udev_device_set_action(struct udev_device *udev_device, const char *action);
extern int udev_device_set_driver(struct udev_device *udev_device, const char *driver);
extern const char *udev_device_get_devpath_old(struct udev_device *udev_device);
extern int udev_device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old);
extern const char *udev_device_get_physdevpath(struct udev_device *udev_device);
extern int udev_device_set_physdevpath(struct udev_device *udev_device, const char *physdevpath);
extern int udev_device_get_timeout(struct udev_device *udev_device);
extern int udev_device_set_timeout(struct udev_device *udev_device, int timeout);
extern int udev_device_get_event_timeout(struct udev_device *udev_device);
extern int udev_device_set_event_timeout(struct udev_device *udev_device, int event_timeout);
extern int udev_device_set_devnum(struct udev_device *udev_device, dev_t devnum);
extern int udev_device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum);
extern int udev_device_get_num_fake_partitions(struct udev_device *udev_device);
extern int udev_device_set_num_fake_partitions(struct udev_device *udev_device, int num);
extern int udev_device_get_devlink_priority(struct udev_device *udev_device);
extern int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio);
extern int udev_device_get_ignore_remove(struct udev_device *udev_device);
extern int udev_device_set_ignore_remove(struct udev_device *udev_device, int ignore);
extern void udev_device_set_info_loaded(struct udev_device *device);

/* libudev-device-db-write.c */
extern int udev_device_update_db(struct udev_device *udev_device);
extern int udev_device_delete_db(struct udev_device *udev_device);
extern int udev_device_rename_db(struct udev_device *udev_device, const char *devpath);

/* libudev-monitor - netlink/unix socket communication  */
extern int udev_monitor_send_device(struct udev_monitor *udev_monitor, struct udev_device *udev_device);
extern int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size);

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
struct udev_list_node {
	struct udev_list_node *next, *prev;
};
extern void udev_list_init(struct udev_list_node *list);
extern int udev_list_is_empty(struct udev_list_node *list);
extern void udev_list_node_append(struct udev_list_node *new, struct udev_list_node *list);
extern void udev_list_node_remove(struct udev_list_node *entry);
#define udev_list_node_foreach(node, list) \
	for (node = (list)->next; \
	     node != list; \
	     node = (node)->next)
#define udev_list_node_foreach_safe(node, tmp, list) \
	for (node = (list)->next, tmp = (node)->next; \
	     node != list; \
	     node = tmp, tmp = (tmp)->next)
extern struct udev_list_entry *udev_list_entry_add(struct udev *udev, struct udev_list_node *list,
						   const char *name, const char *value,
						   int unique, int sort);
extern void udev_list_entry_delete(struct udev_list_entry *entry);
extern void udev_list_entry_remove(struct udev_list_entry *entry);
extern void udev_list_entry_insert_before(struct udev_list_entry *new, struct udev_list_entry *entry);
extern void udev_list_entry_append(struct udev_list_entry *new, struct udev_list_node *list);
extern void udev_list_cleanup_entries(struct udev *udev, struct udev_list_node *name_list);
extern struct udev_list_entry *udev_list_get_entry(struct udev_list_node *list);
extern int udev_list_entry_get_flag(struct udev_list_entry *list_entry);
extern void udev_list_entry_set_flag(struct udev_list_entry *list_entry, int flag);
#define udev_list_entry_foreach_safe(entry, tmp, first) \
	for (entry = first, tmp = udev_list_entry_get_next(entry); \
	     entry != NULL; \
	     entry = tmp, tmp = udev_list_entry_get_next(tmp))

/* libudev-queue */
extern int udev_queue_export_udev_seqnum(struct udev_queue *udev_queue, unsigned long long int seqnum);
extern int udev_queue_export_device_queued(struct udev_queue *udev_queue, struct udev_device *udev_device);
extern int udev_queue_export_device_finished(struct udev_queue *udev_queue, struct udev_device *udev_device);
extern int udev_queue_export_device_failed(struct udev_queue *udev_queue, struct udev_device *udev_device);

/* libudev-utils */
#define UTIL_PATH_SIZE				1024
#define UTIL_LINE_SIZE				2048
#define UTIL_NAME_SIZE				512
#define UDEV_ALLOWED_CHARS_INPUT		"/ $%?,"
extern ssize_t util_get_sys_subsystem(struct udev *udev, const char *syspath, char *subsystem, size_t size);
extern ssize_t util_get_sys_driver(struct udev *udev, const char *syspath, char *driver, size_t size);
extern int util_resolve_sys_link(struct udev *udev, char *syspath, size_t size);
extern int util_log_priority(const char *priority);
extern size_t util_path_encode(char *s, size_t len);
extern size_t util_path_decode(char *s);
extern void util_remove_trailing_chars(char *path, char c);
extern size_t util_strlcpy(char *dst, const char *src, size_t size);
extern size_t util_strlcat(char *dst, const char *src, size_t size);
extern int udev_util_replace_whitespace(const char *str, char *to, size_t len);
extern int udev_util_replace_chars(char *str, const char *white);
extern int udev_util_encode_string(const char *str, char *str_enc, size_t len);
#endif
