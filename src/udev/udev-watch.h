/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int udev_watch_init(void);
int udev_watch_restore(void);
int udev_watch_begin(sd_device *dev);
int udev_watch_end(sd_device *dev);
int udev_watch_lookup(int wd, sd_device **ret);
