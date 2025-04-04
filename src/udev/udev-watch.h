/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

typedef struct Manager Manager;

void manager_push_inotify(Manager *manager);
int manager_init_inotify(Manager *manager, int fd);
int manager_start_inotify(Manager *manager);

int udev_watch_begin(int inotify_fd, sd_device *dev);
int udev_watch_end(int inotify_fd, sd_device *dev);
