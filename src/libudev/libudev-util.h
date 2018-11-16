/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "libudev.h"

#include "macro.h"

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
