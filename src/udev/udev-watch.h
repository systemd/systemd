/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int udev_watch_restore(int inotify_fd);
int udev_watch_begin(int inotify_fd, sd_device *dev);
int udev_watch_end(int inotify_fd, sd_device *dev);
