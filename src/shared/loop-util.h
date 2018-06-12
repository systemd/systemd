/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

typedef struct LoopDevice LoopDevice;

/* Some helpers for setting up loopback block devices */

struct LoopDevice {
        int fd;
        int nr;
        char *node;
        bool relinquished;
};

int loop_device_make(int fd, int open_flags, LoopDevice **ret);
int loop_device_make_by_path(const char *path, int open_flags, LoopDevice **ret);

LoopDevice* loop_device_unref(LoopDevice *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(LoopDevice*, loop_device_unref);

void loop_device_relinquish(LoopDevice *d);
