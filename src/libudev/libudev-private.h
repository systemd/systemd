/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "libudev.h"

#include "hashmap.h"
#include "macro.h"
#include "mkdir.h"
#include "strxcpyx.h"
#include "util.h"

#define READ_END  0
#define WRITE_END 1

/* libudev.c */
int udev_get_rules_path(struct udev *udev, char **path[], usec_t *ts_usec[]);

/* libudev-device.c */
struct udev_device *udev_device_new_from_nulstr(struct udev *udev, char *nulstr, ssize_t buflen);
struct udev_device *udev_device_new_from_synthetic_event(struct udev *udev, const char *syspath, const char *action);
struct udev_device *udev_device_shallow_clone(struct udev_device *old_device);
struct udev_device *udev_device_clone_with_db(struct udev_device *old_device);
int udev_device_copy_properties(struct udev_device *dst, struct udev_device *src);
mode_t udev_device_get_devnode_mode(struct udev_device *udev_device);
uid_t udev_device_get_devnode_uid(struct udev_device *udev_device);
gid_t udev_device_get_devnode_gid(struct udev_device *udev_device);
int udev_device_rename(struct udev_device *udev_device, const char *new_name);
int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink);
void udev_device_cleanup_devlinks_list(struct udev_device *udev_device);
int udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value);
char **udev_device_get_properties_envp(struct udev_device *udev_device);
ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf);
const char *udev_device_get_devpath_old(struct udev_device *udev_device);
const char *udev_device_get_id_filename(struct udev_device *udev_device);
void udev_device_set_is_initialized(struct udev_device *udev_device);
int udev_device_add_tag(struct udev_device *udev_device, const char *tag);
void udev_device_remove_tag(struct udev_device *udev_device, const char *tag);
void udev_device_cleanup_tags_list(struct udev_device *udev_device);
usec_t udev_device_get_usec_initialized(struct udev_device *udev_device);
void udev_device_ensure_usec_initialized(struct udev_device *udev_device, struct udev_device *old_device);
int udev_device_get_devlink_priority(struct udev_device *udev_device);
int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio);
int udev_device_get_watch_handle(struct udev_device *udev_device);
int udev_device_set_watch_handle(struct udev_device *udev_device, int handle);
int udev_device_get_ifindex(struct udev_device *udev_device);
void udev_device_set_info_loaded(struct udev_device *device);
bool udev_device_get_db_persist(struct udev_device *udev_device);
void udev_device_set_db_persist(struct udev_device *udev_device);
void udev_device_read_db(struct udev_device *udev_device);

/* libudev-device-private.c */
int udev_device_update_db(struct udev_device *udev_device);
int udev_device_delete_db(struct udev_device *udev_device);
int udev_device_tag_index(struct udev_device *dev, struct udev_device *dev_old, bool add);

/* libudev-monitor.c - netlink/unix socket communication  */
int udev_monitor_disconnect(struct udev_monitor *udev_monitor);
int udev_monitor_allow_unicast_sender(struct udev_monitor *udev_monitor, struct udev_monitor *sender);
int udev_monitor_send_device(struct udev_monitor *udev_monitor,
                             struct udev_monitor *destination, struct udev_device *udev_device);
int udev_monitor_new_from_netlink_fd(struct udev *udev, const char *name, int fd, struct udev_monitor **ret);

/* libudev-list.c */
struct udev_list {
        Hashmap *entries;
        Iterator iterator;
        bool unique;
};
void udev_list_init(struct udev_list *list, bool unique);
void udev_list_cleanup(struct udev_list *list);
struct udev_list_entry *udev_list_get_entry(struct udev_list *list);
int udev_list_entry_add(struct udev_list *list, const char *name, const char *value, struct udev_list_entry **ret);
void udev_list_entry_free(struct udev_list_entry *entry);
int udev_list_entry_get_num(struct udev_list_entry *entry);
int udev_list_entry_set_num(struct udev_list_entry *entry, int num);

/* libudev-queue.c */
unsigned long long int udev_get_kernel_seqnum(struct udev *udev);
int udev_queue_read_seqnum(FILE *queue_file, unsigned long long int *seqnum);
ssize_t udev_queue_read_devpath(FILE *queue_file, char *devpath, size_t size);
ssize_t udev_queue_skip_devpath(FILE *queue_file);

/* libudev-queue-private.c */
struct udev_queue_export *udev_queue_export_new(struct udev *udev);
struct udev_queue_export *udev_queue_export_unref(struct udev_queue_export *udev_queue_export);
void udev_queue_export_cleanup(struct udev_queue_export *udev_queue_export);
int udev_queue_export_device_queued(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device);
int udev_queue_export_device_finished(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device);

/* libudev-util.c */
#define UTIL_PATH_SIZE                      1024
#define UTIL_NAME_SIZE                       512
#define UTIL_LINE_SIZE                     16384
#define UDEV_ALLOWED_CHARS_INPUT        "/ $%?,"
int util_log_priority(const char *priority);
size_t util_path_encode(const char *src, char *dest, size_t size);
int util_replace_whitespace(const char *str, char *to, size_t len);
int util_replace_chars(char *str, const char *white);
uint32_t util_string_hash32(const char *key);
uint64_t util_string_bloom64(const char *str);

/* libudev-util-private.c */
int util_resolve_subsys_kernel(struct udev *udev, const char *string, char *result, size_t maxsize, int read_value);
