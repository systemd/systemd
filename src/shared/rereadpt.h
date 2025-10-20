/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

typedef enum RereadPartitionTableFlags {
        REREADPT_FORCE_UEVENT = 1 << 0, /* Force a "change" ueven out on partitions we didn't resize/remove/add */
        REREADPT_BSD_LOCK     = 1 << 1, /* Take a BSD lock on the device around the rescan operation */
} RereadPartitionTableFlags;

int rereadpt_fd(int fd, RereadPartitionTableFlags flags);
int rereadpt(sd_device *dev, RereadPartitionTableFlags flags);
