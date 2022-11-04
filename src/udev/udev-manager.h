/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-device.h"
#include "sd-event.h"
#include "sd-netlink.h"

#include "hashmap.h"
#include "list.h"
#include "udev-ctrl.h"
#include "udev-rules.h"

typedef struct Event Event;

typedef struct Manager {
        sd_event *event;
        Hashmap *workers;
        LIST_HEAD(Event, events);
        char *cgroup;
        pid_t pid; /* the process that originally allocated the manager object */
        int log_level;

        UdevRules *rules;
        Hashmap *properties;

        sd_netlink *rtnl;

        sd_device_monitor *monitor;
        UdevCtrl *ctrl;
        int worker_watch[2];

        /* used by udev-watch */
        int inotify_fd;
        sd_event_source *inotify_event;

        sd_event_source *kill_workers_event;

        usec_t last_usec;

        bool udev_node_needs_cleanup;
        bool stop_exec_queue;
        bool exit;
} Manager;
