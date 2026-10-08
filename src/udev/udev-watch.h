/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-forward.h"

int manager_init_device_watch(Manager *manager, int fd);
int manager_start_device_watch(Manager *manager);

void udev_watch_begin(UdevWorker *worker, sd_device *dev);
void udev_watch_end(UdevWorker *worker, sd_device *dev);
