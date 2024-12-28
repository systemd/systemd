/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "hashmap.h"
#include "macro.h"
#include "time-util.h"
#include "udev-config.h"
#include "udev-ctrl.h"
#include "udev-def.h"

typedef struct Event Event;
typedef struct UdevRules UdevRules;
typedef struct Worker Worker;

typedef struct Manager {
        sd_event *event;
        Hashmap *workers;
        LIST_HEAD(Event, events);
        char *cgroup;

        UdevRules *rules;
        Hashmap *properties;

        sd_device_monitor *monitor;
        UdevCtrl *ctrl;
        sd_varlink_server *varlink_server;
        int worker_notify_fd;

        /* used by udev-watch */
        int inotify_fd;
        sd_event_source *inotify_event;

        sd_event_source *kill_workers_event;

        usec_t last_usec;

        UdevConfig config_by_udev_conf;
        UdevConfig config_by_command;
        UdevConfig config_by_kernel;
        UdevConfig config_by_control;
        UdevConfig config;

        bool stop_exec_queue;
        bool exit;
} Manager;

Manager* manager_new(void);
Manager* manager_free(Manager *manager);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_init(Manager *manager);
int manager_main(Manager *manager);
void manager_reload(Manager *manager, bool force);
void manager_exit(Manager *manager);

void notify_ready(Manager *manager);

void manager_kill_workers(Manager *manager, bool force);

bool devpath_conflict(const char *a, const char *b);
