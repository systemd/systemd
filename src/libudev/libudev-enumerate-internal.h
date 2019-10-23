/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "libudev.h"
#include "sd-device.h"

struct udev_device;

sd_device_enumerator *udev_enumerate_get_sd_enumerator(struct udev_enumerate *udev_enumerate);
