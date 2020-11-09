/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

#include "macro.h"

struct udev_list;

struct udev_list *udev_list_new(bool unique);
void udev_list_cleanup(struct udev_list *list);
struct udev_list *udev_list_free(struct udev_list *list);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_list *, udev_list_free);

struct udev_list_entry *udev_list_get_entry(struct udev_list *list);
struct udev_list_entry *udev_list_entry_add(struct udev_list *list, const char *name, const char *value);
