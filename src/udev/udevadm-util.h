/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "udev.h"

struct udev_device *find_device(const char *id, const char *prefix);

static inline void print_version(void) {
        printf("%s\n", PACKAGE_VERSION);
}
