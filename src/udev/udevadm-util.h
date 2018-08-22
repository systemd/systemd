/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "udev.h"

struct udev_device *find_device(const char *id,
                                const char *prefix);
