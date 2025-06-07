/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-forward.h"

void udev_watch_dump(void);

int manager_init_inotify(Manager *manager, int fd);
int manager_start_inotify(Manager *manager);

int manager_add_watch(Manager *manager, sd_device *dev);
int manager_remove_watch(Manager *manager, sd_device *dev);

int udev_watch_begin(UdevWorker *worker, sd_device *dev);
int udev_watch_end(UdevWorker *worker, sd_device *dev);
