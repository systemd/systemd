/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "libudev.h"

struct udev_list_node {
        struct udev_list_node *next, *prev;
};

struct udev_list {
        struct udev_list_node node;
        struct udev_list_entry **entries;
        unsigned entries_cur;
        unsigned entries_max;
        bool unique;
};

void udev_list_init(struct udev_list *list, bool unique);
void udev_list_cleanup(struct udev_list *list);
struct udev_list_entry *udev_list_get_entry(struct udev_list *list);
struct udev_list_entry *udev_list_entry_add(struct udev_list *list, const char *name, const char *value);
