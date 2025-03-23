/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

typedef struct Manager Manager;

int manager_save_watch(Manager *manager, sd_device *dev, const char *s);
int manager_remove_watch(Manager *manager, sd_device *dev);

int manager_serialize(Manager *manager);
int manager_deserialize_fd(Manager *manager, int *fd);
int manager_init_inotify(Manager *manager, int fd);
int manager_start_inotify(Manager *manager);

int udev_watch_begin(int inotify_fd, sd_device *dev);
int udev_watch_end(sd_device *dev);
