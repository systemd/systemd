/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-netlink.h"

#include "errno-list.h"
#include "hashmap.h"
#include "time-util.h"

#define DEFAULT_WORKER_TIMEOUT_USEC (3 * USEC_PER_MINUTE)
#define MIN_WORKER_TIMEOUT_USEC     (1 * USEC_PER_MSEC)

typedef struct UdevRules UdevRules;

typedef struct UdevWorker {
        sd_event *event;
        sd_netlink *rtnl;
        sd_device_monitor *monitor;

        Hashmap *properties;
        UdevRules *rules;

        int pipe_fd;
        int inotify_fd; /* Do not close! */

        usec_t exec_delay_usec;
        usec_t timeout_usec;
        int timeout_signal;
        int log_level;
        bool blockdev_read_only;
} UdevWorker;

/* passed from worker to main process */
typedef enum EventResult {
        EVENT_RESULT_NERRNO_MIN       = -ERRNO_MAX,
        EVENT_RESULT_NERRNO_MAX       = -1,
        EVENT_RESULT_SUCCESS          = 0,
        EVENT_RESULT_EXIT_STATUS_BASE = 0,
        EVENT_RESULT_EXIT_STATUS_MAX  = 255,
        EVENT_RESULT_TRY_AGAIN        = 256, /* when the block device is locked by another process. */
        EVENT_RESULT_SIGNAL_BASE      = 257,
        EVENT_RESULT_SIGNAL_MAX       = EVENT_RESULT_SIGNAL_BASE + _NSIG,
        _EVENT_RESULT_MAX,
        _EVENT_RESULT_INVALID         = -EINVAL,
} EventResult;

void udev_worker_done(UdevWorker *worker);
int udev_worker_main(UdevWorker *worker, sd_device *dev);

void udev_broadcast_result(sd_device_monitor *monitor, sd_device *dev, EventResult result);
int udev_get_whole_disk(sd_device *dev, sd_device **ret_device, const char **ret_devname);
