/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-config.h"
#include "udev-forward.h"

#define DEFAULT_WORKER_TIMEOUT_USEC (3 * USEC_PER_MINUTE)
#define MIN_WORKER_TIMEOUT_USEC     (1 * USEC_PER_MSEC)

typedef struct UdevWorker {
        sd_event *event;
        sd_netlink *rtnl;
        sd_device_monitor *monitor;

        Hashmap *properties;
        UdevRules *rules;

        UdevConfig config;

        pid_t manager_pid;
} UdevWorker;

void udev_worker_done(UdevWorker *worker);
int udev_worker_main(UdevWorker *worker, sd_device *dev);

int udev_get_whole_disk(sd_device *dev, sd_device **ret_device, const char **ret_devname);
