/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int device_new_from_watch_handle(sd_device **ret, int wd);

int udev_watch_restore(int inotify_fd);
int udev_watch_begin(int inotify_fd, sd_device *dev);
int udev_watch_end(int inotify_fd, sd_device *dev);
