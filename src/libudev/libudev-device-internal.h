/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libudev.h"

#include "forward.h"

struct udev_device;

struct udev_device* udev_device_new(struct udev *udev, sd_device *device);
sd_device* udev_device_get_sd_device(struct udev_device *udev_device);
