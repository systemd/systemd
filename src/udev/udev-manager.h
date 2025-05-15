/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"
#include "list.h"
#include "udev-config.h"
#include "udev-forward.h"

/* This should have a higher priority than the device monitor and inotify watch, to make device monitor and
 * inotify event source stopped as soon as possible when the signal is received. Otherwise, we may continue
 * receive events that needs to be serialized anyway. */
#define EVENT_PRIORITY_SIGTERM        (SD_EVENT_PRIORITY_NORMAL - 6)
/* This must have a higher priority than the inotify event source, to make 'remove' uevent received earlier
 * than IN_IGNORED inotify event. */
#define EVENT_PRIORITY_DEVICE_MONITOR (SD_EVENT_PRIORITY_NORMAL - 5)
/* This must have a higher priority than the worker notification, to make IN_IGNORED event received earlier
 * than notifications about requests of adding/removing inotify watches. */
#define EVENT_PRIORITY_INOTIFY_WATCH  (SD_EVENT_PRIORITY_NORMAL - 4)
/* This must have a higher priority than the worker SIGCHLD event, to make notifications about completions of
 * processing events received before SIGCHLD. */
#define EVENT_PRIORITY_WORKER_NOTIFY  (SD_EVENT_PRIORITY_NORMAL - 3)
/* This should have a higher priority than timer events about killing long running worker processes or idle
 * worker processes. */
#define EVENT_PRIORITY_WORKER_SIGCHLD (SD_EVENT_PRIORITY_NORMAL - 2)
/* As said in the above, this should have a lower proority than the SIGCHLD event source. */
#define EVENT_PRIORITY_WORKER_TIMER   (SD_EVENT_PRIORITY_NORMAL - 1)
/* This should have a lower priority than most event sources, but let's process earlier than varlink and the
 * legacy control socket. */
#define EVENT_PRIORITY_SIGHUP         (SD_EVENT_PRIORITY_NORMAL + 1)
/* Let's not interrupt the service by any user process, even that requires privileges. */
#define EVENT_PRIORITY_VARLINK        (SD_EVENT_PRIORITY_NORMAL + 2)
#define EVENT_PRIORITY_CONTROL        (SD_EVENT_PRIORITY_NORMAL + 2)
/* The event is intended to trigger the post-event source, hence can be the lowest priority. */
#define EVENT_PRIORITY_REQUEUE_EVENT  (SD_EVENT_PRIORITY_NORMAL + 3)

typedef struct Manager {
        sd_event *event;
        Hashmap *workers;
        LIST_HEAD(Event, events);
        Event *last_event;
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

        Hashmap *locked_events_by_disk;
        Prioq *locked_events_by_time;
        sd_event_source *requeue_locked_events_timer_event_source;

        usec_t last_usec;

        UdevConfig config_by_udev_conf;
        UdevConfig config_by_command;
        UdevConfig config_by_kernel;
        UdevConfig config_by_control;
        UdevConfig config;

        bool queue_file_created;
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
int manager_reset_kill_workers_timer(Manager *manager);

bool devpath_conflict(const char *a, const char *b);

int manager_requeue_locked_events_by_device(Manager *manager, sd_device *dev);
