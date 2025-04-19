/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "time-util.h"
#include "udev-config.h"
#include "udev-ctrl.h"
#include "udev-def.h"

/* This must have a higher priority than the worker notification, to make IN_IGNORED event received earlier
 * than notifications about requests of adding/removing inotify watches. */
#define EVENT_PRIORITY_INOTIFY_WATCH  (SD_EVENT_PRIORITY_NORMAL - 30)
/* This must have a higher priority than the worker SIGCHLD event, to make notifications about completions of
 * processing events received before SIGCHLD. */
#define EVENT_PRIORITY_WORKER_NOTIFY  (SD_EVENT_PRIORITY_NORMAL - 20)
/* This should have a higher priority than other events, especially timer events about killing long running
 * worker processes or idle worker processes. */
#define EVENT_PRIORITY_WORKER_SIGCHLD (SD_EVENT_PRIORITY_NORMAL - 10)
/* This should have a lower priority to make signal and timer event sources processed earlier. */
#define EVENT_PRIORITY_DEVICE_MONITOR (SD_EVENT_PRIORITY_NORMAL + 10)

typedef struct Event Event;
typedef struct UdevRules UdevRules;
typedef struct UdevSeqnum UdevSeqnum;
typedef struct Worker Worker;

typedef struct Manager {
        sd_event *event;
        Hashmap *workers;
        LIST_HEAD(Event, events);
        UdevSeqnum *seqnum;
        char *cgroup;

        UdevRules *rules;
        Hashmap *properties;

        sd_device_monitor *monitor;
        UdevCtrl *ctrl;
        sd_varlink_server *varlink_server;

        char *worker_notify_socket_path;

        /* used by udev-watch */
        int inotify_fd;
        sd_event_source *inotify_event;
        Set *synthesize_change_child_event_sources;

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

int manager_main(Manager *manager);
void manager_reload(Manager *manager, bool force);
void manager_revert(Manager *manager);
void manager_exit(Manager *manager);

void notify_ready(Manager *manager);

void manager_kill_workers(Manager *manager, int signo);

bool devpath_conflict(const char *a, const char *b);

int event_queue_assume_block_device_unlocked(Manager *manager, sd_device *dev);
