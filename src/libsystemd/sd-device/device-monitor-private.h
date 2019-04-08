/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-device.h"

typedef enum MonitorNetlinkGroup {
        MONITOR_GROUP_NONE,
        MONITOR_GROUP_KERNEL,
        MONITOR_GROUP_UDEV,
        _MONITOR_NETLINK_GROUP_MAX,
        _MONITOR_NETLINK_GROUP_INVALID = -1,
} MonitorNetlinkGroup;

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd);
int device_monitor_disconnect(sd_device_monitor *m);
int device_monitor_allow_unicast_sender(sd_device_monitor *m, sd_device_monitor *sender);
int device_monitor_enable_receiving(sd_device_monitor *m);
int device_monitor_get_fd(sd_device_monitor *m);
int device_monitor_send_device(sd_device_monitor *m, sd_device_monitor *destination, sd_device *device);
int device_monitor_receive_device(sd_device_monitor *m, sd_device **ret);
