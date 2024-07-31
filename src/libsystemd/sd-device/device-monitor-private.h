/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "sd-device.h"

#include "socket-util.h"

typedef enum MonitorNetlinkGroup {
        MONITOR_GROUP_NONE,
        MONITOR_GROUP_KERNEL,
        MONITOR_GROUP_UDEV,
        _MONITOR_NETLINK_GROUP_MAX,
        _MONITOR_NETLINK_GROUP_INVALID = -EINVAL,
} MonitorNetlinkGroup;

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd);
int device_monitor_get_address(sd_device_monitor *m, union sockaddr_union *ret);
int device_monitor_allow_unicast_sender(sd_device_monitor *m, sd_device_monitor *sender);
int device_monitor_send(sd_device_monitor *m, const union sockaddr_union *destination, sd_device *device);
