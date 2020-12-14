/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

#include "macro.h"

/* libudev-util.c */
#define UTIL_PATH_SIZE                      1024
#define UTIL_NAME_SIZE                       512
#define UTIL_LINE_SIZE                     16384

/* Cleanup functions */
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev*, udev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_enumerate*, udev_enumerate_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_hwdb*, udev_hwdb_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_queue*, udev_queue_unref);
