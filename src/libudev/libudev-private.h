/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "libudev.h"

#include "macro.h"
#include "mkdir.h"
#include "strxcpyx.h"
#include "util.h"

/* libudev-list.c */
struct udev_list_node {
        struct udev_list_node *next, *prev;
};
struct udev_list {
        struct udev *udev;
        struct udev_list_node node;
        struct udev_list_entry **entries;
        unsigned entries_cur;
        unsigned entries_max;
        bool unique;
};
void udev_list_node_init(struct udev_list_node *list);
int udev_list_node_is_empty(struct udev_list_node *list);
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
void udev_list_init(struct udev *udev, struct udev_list *list, bool unique);
void udev_list_cleanup(struct udev_list *list);
struct udev_list_entry *udev_list_get_entry(struct udev_list *list);
struct udev_list_entry *udev_list_entry_add(struct udev_list *list, const char *name, const char *value);
void udev_list_entry_delete(struct udev_list_entry *entry);
int udev_list_entry_get_num(struct udev_list_entry *list_entry);
void udev_list_entry_set_num(struct udev_list_entry *list_entry, int num);
#define udev_list_entry_foreach_safe(entry, tmp, first) \
        for (entry = first, tmp = udev_list_entry_get_next(entry); \
             entry != NULL; \
             entry = tmp, tmp = udev_list_entry_get_next(tmp))

/* libudev-util.c */
#define UTIL_PATH_SIZE                      1024
#define UTIL_NAME_SIZE                       512
#define UTIL_LINE_SIZE                     16384
#define UDEV_ALLOWED_CHARS_INPUT        "/ $%?,"
size_t util_path_encode(const char *src, char *dest, size_t size);
int util_replace_whitespace(const char *str, char *to, size_t len);
int util_replace_chars(char *str, const char *white);
int util_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, int read_value);

/* Cleanup functions */
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev*, udev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_enumerate*, udev_enumerate_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_hwdb*, udev_hwdb_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_queue*, udev_queue_unref);
