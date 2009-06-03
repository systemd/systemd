/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
struct udev_device *device_new(struct udev *udev);
const char *udev_get_rules_path(struct udev *udev);
int udev_get_run(struct udev *udev);
struct udev_list_entry *udev_add_property(struct udev *udev, const char *key, const char *value);
struct udev_list_entry *udev_get_properties_list_entry(struct udev *udev);

/* libudev-device */
int udev_device_set_syspath(struct udev_device *udev_device, const char *syspath);
int udev_device_set_subsystem(struct udev_device *udev_device, const char *subsystem);
int udev_device_set_devtype(struct udev_device *udev_device, const char *devtype);
int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode);
int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink);
void udev_device_cleanup_devlinks_list(struct udev_device *udev_device);
struct udev_list_entry *udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value);
struct udev_list_entry *udev_device_add_property_from_string(struct udev_device *udev_device, const char *property);
char **udev_device_get_properties_envp(struct udev_device *udev_device);
ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf);
int udev_device_read_db(struct udev_device *udev_device);
int udev_device_read_uevent_file(struct udev_device *udev_device);
int udev_device_set_action(struct udev_device *udev_device, const char *action);
int udev_device_set_driver(struct udev_device *udev_device, const char *driver);
const char *udev_device_get_devpath_old(struct udev_device *udev_device);
int udev_device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old);
const char *udev_device_get_knodename(struct udev_device *udev_device);
int udev_device_set_knodename(struct udev_device *udev_device, const char *knodename);
int udev_device_get_timeout(struct udev_device *udev_device);
int udev_device_set_timeout(struct udev_device *udev_device, int timeout);
int udev_device_get_event_timeout(struct udev_device *udev_device);
int udev_device_set_event_timeout(struct udev_device *udev_device, int event_timeout);
int udev_device_set_devnum(struct udev_device *udev_device, dev_t devnum);
int udev_device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum);
int udev_device_get_num_fake_partitions(struct udev_device *udev_device);
int udev_device_set_num_fake_partitions(struct udev_device *udev_device, int num);
int udev_device_get_devlink_priority(struct udev_device *udev_device);
int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio);
int udev_device_get_ignore_remove(struct udev_device *udev_device);
int udev_device_set_ignore_remove(struct udev_device *udev_device, int ignore);
int udev_device_get_watch_handle(struct udev_device *udev_device);
int udev_device_set_watch_handle(struct udev_device *udev_device, int handle);
void udev_device_set_info_loaded(struct udev_device *device);

/* libudev-device-db-write.c */
int udev_device_update_db(struct udev_device *udev_device);
int udev_device_delete_db(struct udev_device *udev_device);
int udev_device_rename_db(struct udev_device *udev_device, const char *devpath);

/* libudev-monitor - netlink/unix socket communication  */
int udev_monitor_disconnect(struct udev_monitor *udev_monitor);
int udev_monitor_allow_unicast_sender(struct udev_monitor *udev_monitor, struct udev_monitor *sender);
int udev_monitor_send_device(struct udev_monitor *udev_monitor,
			     struct udev_monitor *destination, struct udev_device *udev_device);
int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size);

/* libudev-ctrl - daemon runtime setup */
struct udev_ctrl;
struct udev_ctrl *udev_ctrl_new_from_socket(struct udev *udev, const char *socket_path);
int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl);
void udev_ctrl_unref(struct udev_ctrl *uctrl);
struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl);
int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority);
int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl);
int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl);
int udev_ctrl_send_reload_rules(struct udev_ctrl *uctrl);
int udev_ctrl_send_settle(struct udev_ctrl *uctrl);
int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key);
int udev_ctrl_send_set_max_childs(struct udev_ctrl *uctrl, int count);
struct udev_ctrl_msg;
struct udev_ctrl_msg *udev_ctrl_msg(struct udev_ctrl *uctrl);
struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl *uctrl);
struct udev_ctrl_msg *udev_ctrl_msg_ref(struct udev_ctrl_msg *ctrl_msg);
void udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_reload_rules(struct udev_ctrl_msg *ctrl_msg);
pid_t udev_ctrl_get_settle(struct udev_ctrl_msg *ctrl_msg);
const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_max_childs(struct udev_ctrl_msg *ctrl_msg);

/* libudev-list */
struct udev_list_node {
	struct udev_list_node *next, *prev;
};
void udev_list_init(struct udev_list_node *list);
int udev_list_is_empty(struct udev_list_node *list);
void udev_list_node_append(struct udev_list_node *new, struct udev_list_node *list);
void udev_list_node_remove(struct udev_list_node *entry);
#define udev_list_node_foreach(node, list) \
	for (node = (list)->next; \
	     node != list; \
	     node = (node)->next)
#define udev_list_node_foreach_safe(node, tmp, list) \
	for (node = (list)->next, tmp = (node)->next; \
	     node != list; \
	     node = tmp, tmp = (tmp)->next)
struct udev_list_entry *udev_list_entry_add(struct udev *udev, struct udev_list_node *list,
						   const char *name, const char *value,
						   int unique, int sort);
void udev_list_entry_delete(struct udev_list_entry *entry);
void udev_list_entry_remove(struct udev_list_entry *entry);
void udev_list_entry_insert_before(struct udev_list_entry *new, struct udev_list_entry *entry);
void udev_list_entry_append(struct udev_list_entry *new, struct udev_list_node *list);
void udev_list_cleanup_entries(struct udev *udev, struct udev_list_node *name_list);
struct udev_list_entry *udev_list_get_entry(struct udev_list_node *list);
int udev_list_entry_get_flag(struct udev_list_entry *list_entry);
void udev_list_entry_set_flag(struct udev_list_entry *list_entry, int flag);
#define udev_list_entry_foreach_safe(entry, tmp, first) \
	for (entry = first, tmp = udev_list_entry_get_next(entry); \
	     entry != NULL; \
	     entry = tmp, tmp = udev_list_entry_get_next(tmp))

/* libudev-queue */
unsigned long long int udev_get_kernel_seqnum(struct udev *udev);
int udev_queue_read_seqnum(FILE *queue_file, unsigned long long int *seqnum);
ssize_t udev_queue_read_devpath(FILE *queue_file, char *devpath, size_t size);
ssize_t udev_queue_skip_devpath(FILE *queue_file);

/* libudev-queue-export */
struct udev_queue_export *udev_queue_export_new(struct udev *udev);
void udev_queue_export_unref(struct udev_queue_export *udev_queue_export);
void udev_queue_export_cleanup(struct udev_queue_export *udev_queue_export);
int udev_queue_export_device_queued(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device);
int udev_queue_export_device_finished(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device);
int udev_queue_export_device_failed(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device);

/* libudev-utils */
#define UTIL_PATH_SIZE				1024
#define UTIL_LINE_SIZE				2048
#define UTIL_NAME_SIZE				512
#define UDEV_ALLOWED_CHARS_INPUT		"/ $%?,"
ssize_t util_get_sys_subsystem(struct udev *udev, const char *syspath, char *subsystem, size_t size);
ssize_t util_get_sys_driver(struct udev *udev, const char *syspath, char *driver, size_t size);
int util_resolve_sys_link(struct udev *udev, char *syspath, size_t size);
int util_log_priority(const char *priority);
size_t util_path_encode(const char *src, char *dest, size_t size);
size_t util_path_decode(char *s);
void util_remove_trailing_chars(char *path, char c);
size_t util_strpcpy(char **dest, size_t size, const char *src);
size_t util_strpcpyl(char **dest, size_t size, const char *src, ...) __attribute__ ((sentinel));
size_t util_strscpy(char *dest, size_t size, const char *src);
size_t util_strscpyl(char *dest, size_t size, const char *src, ...) __attribute__ ((sentinel));
int udev_util_replace_whitespace(const char *str, char *to, size_t len);
int udev_util_replace_chars(char *str, const char *white);
int udev_util_encode_string(const char *str, char *str_enc, size_t len);
void util_set_fd_cloexec(int fd);
unsigned int util_string_hash32(const char *str);
#endif
