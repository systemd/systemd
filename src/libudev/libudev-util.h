/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

#include "forward.h"

/* Cleanup functions */
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev*, udev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_enumerate*, udev_enumerate_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_hwdb*, udev_hwdb_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_queue*, udev_queue_unref);
