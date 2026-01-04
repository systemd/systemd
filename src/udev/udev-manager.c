/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "cgroup-util.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "list.h"
#include "notify-recv.h"
#include "pidref.h"
#include "prioq.h"
#include "process-util.h"
#include "selinux-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-builtin.h"
#include "udev-config.h"
#include "udev-ctrl.h"
#include "udev-error.h"
#include "udev-manager.h"
#include "udev-manager-ctrl.h"
#include "udev-rules.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-varlink.h"
#include "udev-watch.h"
#include "udev-worker.h"

#define EVENT_REQUEUE_INTERVAL_USEC (200 * USEC_PER_MSEC)
#define EVENT_REQUEUE_TIMEOUT_USEC  (3 * USEC_PER_MINUTE)

typedef enum EventState {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
        EVENT_LOCKED,
} EventState;

typedef struct Event {
        Manager *manager;
        Worker *worker;
        EventState state;

        sd_device *dev;

        sd_device_action_t action;
        uint64_t seqnum;
        const char *id;
        const char *devpath;
        const char *devpath_old;
        const char *devnode;

        /* Used when the device is locked by another program. */
        usec_t requeue_next_usec;
        usec_t requeue_timeout_usec;
        unsigned locked_event_prioq_index;
        char *whole_disk;
        LIST_FIELDS(Event, same_disk);

        bool dependencies_built;
        Set *blocker_events;
        Set *blocking_events;

        LIST_FIELDS(Event, event);
} Event;

typedef enum WorkerState {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
} WorkerState;

typedef struct Worker {
        Manager *manager;
        PidRef pidref;
        sd_event_source *child_event_source;
        sd_event_source *timeout_warning_event_source;
        sd_event_source *timeout_kill_event_source;
        union sockaddr_union address;
        WorkerState state;
        Event *event;
} Worker;

static void event_clear_dependencies(Event *event) {
        assert(event);

        Event *e;
        while ((e = set_steal_first(event->blocker_events)))
                assert_se(set_remove(e->blocking_events, event) == event);
        event->blocker_events = set_free(event->blocker_events);

        while ((e = set_steal_first(event->blocking_events)))
                assert_se(set_remove(e->blocker_events, event) == event);
        event->blocking_events = set_free(event->blocking_events);

        event->dependencies_built = false;
}

static void event_unset_whole_disk(Event *event) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(event)->manager);

        if (!event->whole_disk)
                return;

        if (event->same_disk_prev)
                /* If this is not the first event, then simply remove this event. */
                event->same_disk_prev->same_disk_next = event->same_disk_next;
        else if (event->same_disk_next)
                /* If this is the first event, replace with the next event. */
                assert_se(hashmap_replace(manager->locked_events_by_disk, event->same_disk_next->whole_disk, event->same_disk_next) >= 0);
        else
                /* Otherwise, remove the entry. */
                assert_se(hashmap_remove(manager->locked_events_by_disk, event->whole_disk) == event);

        if (event->same_disk_next)
                event->same_disk_next->same_disk_prev = event->same_disk_prev;

        event->same_disk_prev = event->same_disk_next = NULL;

        event->whole_disk = mfree(event->whole_disk);
}

static Event* event_free(Event *event) {
        if (!event)
                return NULL;

        if (event->manager) {
                event_unset_whole_disk(event);
                prioq_remove(event->manager->locked_events_by_time, event, &event->locked_event_prioq_index);

                if (event->manager->last_event == event)
                        event->manager->last_event = event->event_prev;
                LIST_REMOVE(event, event->manager->events, event);
        }

        if (event->worker)
                event->worker->event = NULL;

        event_clear_dependencies(event);

        sd_device_unref(event->dev);

        return mfree(event);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Event*, event_free);

static Worker* worker_free(Worker *worker) {
        if (!worker)
                return NULL;

        if (worker->manager)
                hashmap_remove(worker->manager->workers, &worker->pidref);

        sd_event_source_disable_unref(worker->child_event_source);
        sd_event_source_unref(worker->timeout_warning_event_source);
        sd_event_source_unref(worker->timeout_kill_event_source);
        pidref_done(&worker->pidref);
        event_free(worker->event);

        return mfree(worker);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Worker*, worker_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                worker_hash_op,
                PidRef,
                pidref_hash_func,
                pidref_compare_func,
                Worker,
                worker_free);

Manager* manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        udev_builtin_exit();

        hashmap_free(manager->properties);
        udev_rules_free(manager->rules);

        hashmap_free(manager->workers);
        while (manager->events)
                event_free(manager->events);

        prioq_free(manager->locked_events_by_time);
        hashmap_free(manager->locked_events_by_disk);
        sd_event_source_unref(manager->requeue_locked_events_timer_event_source);

        safe_close(manager->inotify_fd);

        free(manager->worker_notify_socket_path);

        sd_device_monitor_unref(manager->monitor);

        udev_ctrl_unref(manager->ctrl);
        sd_varlink_server_unref(manager->varlink_server);

        sd_event_source_unref(manager->inotify_event);
        set_free(manager->synthesize_change_child_event_sources);
        sd_event_source_unref(manager->kill_workers_event);
        sd_event_unref(manager->event);

        free(manager->cgroup);
        return mfree(manager);
}

Manager* manager_new(void) {
        Manager *manager;

        manager = new(Manager, 1);
        if (!manager)
                return NULL;

        *manager = (Manager) {
                .inotify_fd = -EBADF,
                .config_by_udev_conf = UDEV_CONFIG_INIT,
                .config_by_command = UDEV_CONFIG_INIT,
                .config_by_kernel = UDEV_CONFIG_INIT,
                .config_by_control = UDEV_CONFIG_INIT,
                .config = UDEV_CONFIG_INIT,
        };

        return manager;
}

void manager_kill_workers(Manager *manager, int signo) {
        assert(manager);

        Worker *worker;
        HASHMAP_FOREACH(worker, manager->workers) {
                worker->state = WORKER_KILLED;
                (void) pidref_kill(&worker->pidref, signo);
        }
}

static int on_kill_workers_event(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        log_debug("Cleaning up idle workers.");
        manager_kill_workers(manager, SIGTERM);

        return 0;
}

int manager_reset_kill_workers_timer(Manager *manager) {
        int r;

        assert(manager);

        if (hashmap_isempty(manager->workers)) {
                /* There are no workers. Disabling unnecessary timer event source. */
                r = sd_event_source_set_enabled(manager->kill_workers_event, SD_EVENT_OFF);
                if (r < 0)
                        return log_warning_errno(r, "Failed to disable timer event source for cleaning up workers: %m");
        } else {
                r = event_reset_time_relative(
                                manager->event,
                                &manager->kill_workers_event,
                                CLOCK_MONOTONIC,
                                3 * USEC_PER_SEC,
                                USEC_PER_SEC,
                                on_kill_workers_event,
                                manager,
                                EVENT_PRIORITY_WORKER_TIMER,
                                "kill-workers-event",
                                /* force_reset = */ false);
                if (r < 0)
                        return log_warning_errno(r, "Failed to enable timer event source for cleaning up workers: %m");
        }

        return 0;
}

void manager_exit(Manager *manager) {
        assert(manager);

        manager->exit = true;

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_STOPPING_MESSAGE);

        /* close sources of new events and discard buffered events */
        manager->ctrl = udev_ctrl_unref(manager->ctrl);
        manager->varlink_server = sd_varlink_server_unref(manager->varlink_server);
        (void) manager_serialize_config(manager);

        /* Disable the event source, but do not close the inotify fd here, as we may still receive
         * notification messages about requests to add or remove inotify watches. */
        manager->inotify_event = sd_event_source_disable_unref(manager->inotify_event);

        /* Disable the device monitor but do not free device monitor, as it may be used when a worker failed,
         * and the manager needs to broadcast the kernel event assigned to the worker to libudev listeners.
         * Note, here we cannot use sd_device_monitor_stop(), as it changes the multicast group of the socket. */
        (void) sd_event_source_set_enabled(sd_device_monitor_get_event_source(manager->monitor), SD_EVENT_OFF);
        (void) sd_device_monitor_detach_event(manager->monitor);

        /* Kill all workers with SIGTERM, and disable unnecessary timer event source. */
        manager_kill_workers(manager, SIGTERM);
        manager->kill_workers_event = sd_event_source_disable_unref(manager->kill_workers_event);

        (void) event_source_disable(manager->requeue_locked_events_timer_event_source);
}

void notify_ready(Manager *manager) {
        int r;

        assert(manager);

        r = sd_notifyf(/* unset_environment= */ false,
                       "READY=1\n"
                       "STATUS=Processing with %u children at max", manager->config.children_max);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
}

/* reload requested, HUP signal received, rules changed, builtin changed */
void manager_reload(Manager *manager, bool force) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        usec_t now_usec;
        int r;

        assert(manager);

        assert_se(sd_event_now(manager->event, CLOCK_MONOTONIC, &now_usec) >= 0);
        if (!force && now_usec < usec_add(manager->last_usec, 3 * USEC_PER_SEC))
                /* check for changed config, every 3 seconds at most */
                return;
        manager->last_usec = now_usec;

        /* Reload SELinux label database, to make the child inherit the up-to-date database. */
        mac_selinux_maybe_reload();

        UdevReloadFlags flags = udev_builtin_should_reload();
        if (udev_rules_should_reload(manager->rules))
                flags |= UDEV_RELOAD_RULES | UDEV_RELOAD_KILL_WORKERS;
        if (flags == 0 && !force)
                /* Neither .rules files nor config files for builtins e.g. .link files changed. It is not
                 * necessary to reload configs. Note, udev.conf is not checked in the above, hence reloaded
                 * when explicitly requested or at least one .rules file or friend is updated. */
                return;

        (void) notify_reloading();

        flags |= manager_reload_config(manager);

        if (FLAGS_SET(flags, UDEV_RELOAD_KILL_WORKERS))
                manager_kill_workers(manager, SIGTERM);

        udev_builtin_reload(flags);

        if (FLAGS_SET(flags, UDEV_RELOAD_RULES)) {
                r = udev_rules_load(&rules, manager->config.resolve_name_timing, /* extra = */ NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to read udev rules, using the previously loaded rules, ignoring: %m");
                else
                        udev_rules_free_and_replace(manager->rules, rules);
        }

        notify_ready(manager);
}

void manager_revert(Manager *manager) {
        assert(manager);

        UdevReloadFlags flags = manager_revert_config(manager);
        if (flags == 0)
                return;

        assert(flags == UDEV_RELOAD_KILL_WORKERS);
        manager_kill_workers(manager, SIGTERM);
}

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_(worker_freep) Worker *worker = ASSERT_PTR(userdata);
        sd_device *dev = worker->event ? ASSERT_PTR(worker->event->dev) : NULL;

        assert(si);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0) {
                        log_device_debug(dev, "Worker ["PID_FMT"] exited.", si->si_pid);
                        return 0;
                }

                log_device_warning(dev, "Worker ["PID_FMT"] exited with return code %i.",
                                   si->si_pid, si->si_status);
                if (!dev)
                        return 0;

                (void) device_add_exit_status(dev, si->si_status);
                break;

        case CLD_KILLED:
        case CLD_DUMPED:
                log_device_warning(dev, "Worker ["PID_FMT"] terminated by signal %i (%s).",
                                   si->si_pid, si->si_status, signal_to_string(si->si_status));
                if (!dev)
                        return 0;

                (void) device_add_signal(dev, si->si_status);
                break;

        default:
                assert_not_reached();
        }

        (void) device_broadcast_on_error(dev, worker->manager->monitor);
        return 0;
}

static int worker_new(Worker **ret, Manager *manager, sd_device_monitor *worker_monitor, PidRef *pidref) {
        _cleanup_(worker_freep) Worker *worker = NULL;
        int r;

        assert(ret);
        assert(manager);
        assert(worker_monitor);
        assert(pidref);

        /* This takes and invalidates pidref even on some error cases. */

        worker = new(Worker, 1);
        if (!worker)
                return -ENOMEM;

        *worker = (Worker) {
                .pidref = TAKE_PIDREF(*pidref),
        };

        r = device_monitor_get_address(worker_monitor, &worker->address);
        if (r < 0)
                return r;

        r = event_add_child_pidref(manager->event, &worker->child_event_source, &worker->pidref, WEXITED, on_sigchld, worker);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(worker->child_event_source, EVENT_PRIORITY_WORKER_SIGCHLD);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&manager->workers, &worker_hash_op, &worker->pidref, worker);
        if (r < 0)
                return r;

        worker->manager = manager;

        *ret = TAKE_PTR(worker);
        return 0;
}

static int on_worker_timeout_kill(sd_event_source *s, uint64_t usec, void *userdata) {
        Worker *worker = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(worker->manager);
        Event *event = ASSERT_PTR(worker->event);

        (void) pidref_kill_and_sigcont(&worker->pidref, manager->config.timeout_signal);
        worker->state = WORKER_KILLED;

        log_device_error(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" killed.", worker->pidref.pid, event->seqnum);
        return 0;
}

static int on_worker_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Worker *worker = ASSERT_PTR(userdata);
        Event *event = ASSERT_PTR(worker->event);

        log_device_warning(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" is taking a long time.", worker->pidref.pid, event->seqnum);
        return 0;
}

static void worker_attach_event(Worker *worker, Event *event) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(worker)->manager);

        assert(event);
        assert(event->state == EVENT_QUEUED);
        assert(!event->worker);
        assert(IN_SET(worker->state, WORKER_UNDEF, WORKER_IDLE));
        assert(!worker->event);

        worker->state = WORKER_RUNNING;
        worker->event = event;
        event->state = EVENT_RUNNING;
        event->worker = worker;

        (void) event_reset_time_relative(
                        manager->event,
                        &worker->timeout_warning_event_source,
                        CLOCK_MONOTONIC,
                        udev_warn_timeout(manager->config.timeout_usec),
                        USEC_PER_SEC,
                        on_worker_timeout_warning,
                        worker,
                        EVENT_PRIORITY_WORKER_TIMER,
                        "worker-timeout-warn",
                        /* force_reset = */ true);

        (void) event_reset_time_relative(
                        manager->event,
                        &worker->timeout_kill_event_source,
                        CLOCK_MONOTONIC,
                        manager_kill_worker_timeout(manager),
                        USEC_PER_SEC,
                        on_worker_timeout_kill,
                        worker,
                        EVENT_PRIORITY_WORKER_TIMER,
                        "worker-timeout-kill",
                        /* force_reset = */ true);
}

static Event* worker_detach_event(Worker *worker) {
        assert(worker);

        Event *event = TAKE_PTR(worker->event);
        if (event)
                assert_se(TAKE_PTR(event->worker) == worker);

        if (worker->state != WORKER_KILLED)
                worker->state = WORKER_IDLE;

        (void) event_source_disable(worker->timeout_warning_event_source);
        (void) event_source_disable(worker->timeout_kill_event_source);

        return event;
}

static int worker_spawn(Manager *manager, Event *event) {
        int r;

        assert(manager);
        assert(event);

        /* listen for new events */
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *worker_monitor = NULL;
        r = device_monitor_new_full(&worker_monitor, MONITOR_GROUP_NONE, -EBADF);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(worker_monitor, "worker");

        /* allow the main daemon netlink address to send devices to the worker */
        r = device_monitor_allow_unicast_sender(worker_monitor, manager->monitor);
        if (r < 0)
                return log_error_errno(r, "Worker: Failed to set unicast sender: %m");

        pid_t manager_pid = getpid_cached();
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork("(udev-worker)", FORK_DEATHSIG_SIGTERM, &pidref);
        if (r < 0) {
                event->state = EVENT_QUEUED;
                return log_error_errno(r, "Failed to fork() worker: %m");
        }
        if (r == 0) {
                _cleanup_(udev_worker_done) UdevWorker w = {
                        .monitor = TAKE_PTR(worker_monitor),
                        .properties = TAKE_PTR(manager->properties),
                        .rules = TAKE_PTR(manager->rules),
                        .config = manager->config,
                        .manager_pid = manager_pid,
                };

                if (setenv("NOTIFY_SOCKET", manager->worker_notify_socket_path, /* overwrite = */ true) < 0) {
                        log_error_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Worker process */
                r = udev_worker_main(&w, event->dev);
                log_close();
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        Worker *worker;
        r = worker_new(&worker, manager, worker_monitor, &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to create worker object: %m");

        worker_attach_event(worker, event);

        log_device_debug(event->dev, "Worker ["PID_FMT"] is forked for processing SEQNUM=%"PRIu64".", worker->pidref.pid, event->seqnum);
        return 0;
}

static int event_run(Event *event) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(event)->manager);
        int r;

        log_device_uevent(event->dev, "Device ready for processing");

        Worker *worker;
        HASHMAP_FOREACH(worker, manager->workers) {
                if (worker->state != WORKER_IDLE)
                        continue;

                r = device_monitor_send(manager->monitor, &worker->address, event->dev);
                if (r < 0) {
                        log_device_error_errno(event->dev, r, "Worker ["PID_FMT"] did not accept message, killing the worker: %m",
                                               worker->pidref.pid);
                        (void) pidref_kill(&worker->pidref, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_attach_event(worker, event);
                return 0;
        }

        /* start new worker and pass initial device */
        assert(hashmap_size(manager->workers) < manager->config.children_max);
        r = worker_spawn(manager, event);
        if (r < 0)
                return r;

        return 0;
}

bool devpath_conflict(const char *a, const char *b) {
        /* This returns true when two paths are equivalent, or one is a child of another. */

        if (!a || !b)
                return false;

        for (; *a != '\0' && *b != '\0'; a++, b++)
                if (*a != *b)
                        return false;

        return *a == '/' || *b == '/' || *a == *b;
}

static int event_build_dependencies(Event *event) {
        int r;

        assert(event);

        /* lookup event for identical, parent, child device */

        if (event->dependencies_built)
                return 0;

        LIST_FOREACH_BACKWARDS(event, e, event->event_prev) {
                if (!streq_ptr(event->id, e->id) &&
                    !devpath_conflict(event->devpath, e->devpath) &&
                    !devpath_conflict(event->devpath, e->devpath_old) &&
                    !devpath_conflict(event->devpath_old, e->devpath) &&
                    !(event->devnode && streq_ptr(event->devnode, e->devnode)))
                        continue;

                r = set_ensure_put(&event->blocker_events, NULL, e);
                if (r < 0)
                        return r;

                r = set_ensure_put(&e->blocking_events, NULL, event);
                if (r < 0) {
                        assert_se(set_remove(event->blocker_events, e) == e);
                        return r;
                }

                log_device_debug(event->dev, "SEQNUM=%" PRIu64 " blocked by SEQNUM=%" PRIu64,
                                 event->seqnum, e->seqnum);
        }

        event->dependencies_built = true;
        return 0;
}

static bool manager_can_process_event(Manager *manager) {
        static bool children_max_reached_logged = false;

        assert(manager);

        /* Check if there is a free room for processing an event. */

        if (hashmap_size(manager->workers) < manager->config.children_max)
                goto yes_we_can; /* new worker can be spawned */

        Worker *worker;
        HASHMAP_FOREACH(worker, manager->workers)
                if (worker->state == WORKER_IDLE)
                        goto yes_we_can; /* found an idle worker */

        /* Avoid spamming the debug logs if the limit is already reached and
         * many events still need to be processed */
        if (!children_max_reached_logged) {
                log_debug("Maximum number (%u) of children reached.", hashmap_size(manager->workers));
                children_max_reached_logged = true;
        }

        return false;

yes_we_can:
        /* Re-enable the debug message for the next batch of events */
        children_max_reached_logged = false;
        return true;
}

static int event_queue_start(Manager *manager) {
        int r;

        assert(manager);
        assert(!manager->exit);

        if (!manager->events || manager->stop_exec_queue)
                return 0;

        r = event_source_disable(manager->kill_workers_event);
        if (r < 0)
                log_warning_errno(r, "Failed to disable event source for cleaning up idle workers, ignoring: %m");

        manager_reload(manager, /* force = */ false);

        /* manager_reload() may kill idle workers, hence we may not be possible to start processing an event.
         * Let's check that and return earlier if we cannot. */
        if (!manager_can_process_event(manager))
                return 0;

        LIST_FOREACH(event, event, manager->events) {
                if (event->state != EVENT_QUEUED)
                        continue;

                r = event_build_dependencies(event);
                if (r < 0)
                        log_device_warning_errno(event->dev, r,
                                                 "Failed to check dependencies for event (SEQNUM=%"PRIu64", ACTION=%s), ignoring: %m",
                                                 event->seqnum, strna(device_action_to_string(event->action)));

                /* do not start event if parent or child event is still running or queued */
                if (!set_isempty(event->blocker_events))
                        continue;

                r = event_run(event);
                if (r < 0)
                        return r;

                /* A worker is activated now. Let's check if we can process more events. */
                if (!manager_can_process_event(manager))
                        break;
        }

        return 0;
}

static int on_requeue_locked_events(sd_event_source *s, uint64_t usec, void *userdata) {
        /* This does nothing. The on_post() callback will requeue locked events. */
        return 1;
}

static int manager_requeue_locked_events(Manager *manager) {
        usec_t now_usec = 0;
        int r;

        assert(manager);

        for (;;) {
                Event *event = prioq_peek(manager->locked_events_by_time);
                if (!event)
                        return event_source_disable(manager->requeue_locked_events_timer_event_source);

                if (now_usec == 0) {
                        r = sd_event_now(manager->event, CLOCK_MONOTONIC, &now_usec);
                        if (r < 0)
                                return r;
                }

                if (event->requeue_next_usec > now_usec)
                        return event_reset_time(
                                        manager->event,
                                        &manager->requeue_locked_events_timer_event_source,
                                        CLOCK_MONOTONIC,
                                        event->requeue_next_usec,
                                        USEC_PER_SEC,
                                        on_requeue_locked_events,
                                        /* userdata = */ NULL,
                                        EVENT_PRIORITY_REQUEUE_EVENT,
                                        "requeue-locked-events",
                                        /* force_reset = */ true);

                assert_se(prioq_pop(manager->locked_events_by_time) == event);
                event_unset_whole_disk(event);
                event->state = EVENT_QUEUED;
        }
}

int manager_requeue_locked_events_by_device(Manager *manager, sd_device *dev) {
        int r;

        /* When a new event for a block device is queued or we get an inotify event, assume that the
         * device is not locked anymore. The assumption may not be true, but that should not cause any
         * issues, as in that case events will be requeued soon. */

        if (hashmap_isempty(manager->locked_events_by_disk))
                return 0;

        const char *devname;
        r = udev_get_whole_disk(dev, NULL, &devname);
        if (r <= 0)
                return r;

        Event *first = hashmap_remove(manager->locked_events_by_disk, devname);
        if (!first)
                return 0;

        Event *event;
        while ((event = LIST_POP(same_disk, first))) {
                assert_se(prioq_remove(manager->locked_events_by_time, event, &event->locked_event_prioq_index) > 0);
                event->whole_disk = mfree(event->whole_disk);
                event->state = EVENT_QUEUED;
        }

        return 0;
}

static int locked_event_compare(const Event *x, const Event *y) {
        return CMP(x->requeue_next_usec, y->requeue_next_usec);
}

static int event_enter_locked(Event *event, const char *whole_disk) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(event)->manager);
        sd_device *dev = ASSERT_PTR(event->dev);
        usec_t now_usec;
        int r;

        /* add a short delay to suppress busy loop */
        r = sd_event_now(manager->event, CLOCK_MONOTONIC, &now_usec);
        if (r < 0)
                return log_device_warning_errno(
                                dev, r,
                                "Failed to get current time, skipping event (SEQNUM=%"PRIu64", ACTION=%s): %m",
                                event->seqnum, strna(device_action_to_string(event->action)));

        if (event->requeue_timeout_usec > 0 && event->requeue_timeout_usec <= now_usec)
                return log_device_warning_errno(
                                dev, SYNTHETIC_ERRNO(ETIMEDOUT),
                                "The underlying block device is locked by a process more than %s, skipping event (SEQNUM=%"PRIu64", ACTION=%s).",
                                FORMAT_TIMESPAN(EVENT_REQUEUE_TIMEOUT_USEC, USEC_PER_MINUTE),
                                event->seqnum, strna(device_action_to_string(event->action)));

        event->requeue_next_usec = usec_add(now_usec, EVENT_REQUEUE_INTERVAL_USEC);
        if (event->requeue_timeout_usec == 0)
                event->requeue_timeout_usec = usec_add(now_usec, EVENT_REQUEUE_TIMEOUT_USEC);

        if (isempty(whole_disk))
                return log_device_warning_errno(
                                dev, SYNTHETIC_ERRNO(EBADMSG),
                                "Unexpected notify message received, skipping event (SEQNUM=%"PRIu64", ACTION=%s).",
                                event->seqnum, strna(device_action_to_string(event->action)));

        _cleanup_free_ char *whole_disk_copy = strdup(whole_disk);
        if (!whole_disk_copy)
                return log_oom();

        Event *first = hashmap_get(manager->locked_events_by_disk, whole_disk_copy);
        LIST_PREPEND(same_disk, first, event);

        r = hashmap_ensure_replace(&manager->locked_events_by_disk, &path_hash_ops, whole_disk_copy, first);
        if (r < 0) {
                LIST_REMOVE(same_disk, first, event);
                return log_oom();
        }
        event->whole_disk = TAKE_PTR(whole_disk_copy);

        r = prioq_ensure_put(&manager->locked_events_by_time, locked_event_compare, event, &event->locked_event_prioq_index);
        if (r < 0)
                return log_oom();

        event->state = EVENT_LOCKED;
        return 0;
}

static int event_queue_insert(Manager *manager, sd_device *dev) {
        const char *devpath, *devpath_old = NULL, *id = NULL, *devnode = NULL;
        sd_device_action_t action;
        uint64_t seqnum;
        int r;

        assert(manager);
        assert(dev);

        /* We only accepts devices received by device monitor. */
        r = sd_device_get_seqnum(dev, &seqnum);
        if (r < 0)
                return r;

        r = sd_device_get_action(dev, &action);
        if (r < 0)
                return r;

        r = sd_device_get_devpath(dev, &devpath);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(dev, "DEVPATH_OLD", &devpath_old);
        if (r < 0 && r != -ENOENT)
                return r;

        r = sd_device_get_device_id(dev, &id);
        if (r < 0 && r != -ENOENT)
                return r;

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0 && r != -ENOENT)
                return r;

        _cleanup_(event_freep) Event *event = new(Event, 1);
        if (!event)
                return -ENOMEM;

        *event = (Event) {
                .dev = sd_device_ref(dev),
                .seqnum = seqnum,
                .action = action,
                .id = id,
                .devpath = devpath,
                .devpath_old = devpath_old,
                .devnode = devnode,
                .state = EVENT_QUEUED,
                .locked_event_prioq_index = PRIOQ_IDX_NULL,
        };

        Event *prev = NULL;
        LIST_FOREACH_BACKWARDS(event, e, manager->last_event) {
                if (e->seqnum < event->seqnum) {
                        prev = e;
                        break;
                }
                if (e->seqnum == event->seqnum)
                        return log_device_warning_errno(dev, SYNTHETIC_ERRNO(EALREADY),
                                                        "The event (SEQNUM=%"PRIu64") has been already queued.",
                                                        event->seqnum);

                /* Inserting an event in an earlier place may change dependency tree. Let's rebuild it later. */
                event_clear_dependencies(e);
        }

        LIST_INSERT_AFTER(event, manager->events, prev, event);
        if (prev == manager->last_event)
                manager->last_event = event;
        else
                log_device_debug(dev, "Unordered event is received (last queued event seqnum=%"PRIu64", newly received event seqnum=%"PRIu64"), reordering.",
                                 manager->last_event->seqnum, event->seqnum);

        event->manager = manager;
        TAKE_PTR(event);
        log_device_uevent(dev, "Device is queued");

        if (!manager->queue_file_created) {
                r = touch("/run/udev/queue");
                if (r < 0)
                        log_warning_errno(r, "Failed to touch /run/udev/queue, ignoring: %m");
                else
                        manager->queue_file_created = true;
        }

        return 0;
}

static int manager_serialize_events(Manager *manager) {
        int r;

        assert(manager);

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *storage = NULL;
        r = device_monitor_new_full(&storage, MONITOR_GROUP_NONE, -EBADF);
        if (r < 0)
                return log_warning_errno(r, "Failed to create new device monitor instance: %m");

        union sockaddr_union a;
        r = device_monitor_get_address(storage, &a);
        if (r < 0)
                return log_warning_errno(r, "Failed to get address of device monitor socket: %m");

        uint64_t n = 0;
        LIST_FOREACH(event, event, manager->events) {
                if (event->state != EVENT_QUEUED)
                        continue;

                r = device_monitor_send(storage, &a, event->dev);
                if (r < 0) {
                        log_device_warning_errno(event->dev, r, "Failed to save event to socket storage, ignoring: %m");
                        continue;
                }

                n++;
        }

        if (n == 0)
                return 0;

        r = notify_push_fd(sd_device_monitor_get_fd(storage), "event-serialization");
        if (r < 0)
                return log_warning_errno(r, "Failed to push event serialization fd to service manager: %m");

        log_debug("Serialized %"PRIu64" events.", n);
        return 0;
}

static int manager_deserialize_events(Manager *manager, int *fd) {
        int r;

        assert(manager);
        assert(fd);
        assert(*fd >= 0);

        /* This may take and invalidate passed file descriptor even on failure. */

        /* At this stage, we have not receive any events from the kernel, hence should be empty. */
        if (manager->events)
                return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple event storage socket (%i).", *fd);

        r = sd_is_socket(*fd, AF_NETLINK, SOCK_RAW, /* listening = */ -1);
        if (r < 0)
                return log_warning_errno(r, "Failed to verify type of event storage socket (%i): %m", *fd);
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Received invalid event storage socket (%i).", *fd);

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *storage = NULL;
        r = device_monitor_new_full(&storage, MONITOR_GROUP_NONE, *fd);
        if (r < 0)
                return log_warning_errno(r, "Failed to initialize event storage: %m");
        TAKE_FD(*fd);

        r = device_monitor_allow_unicast_sender(storage, storage);
        if (r < 0)
                return log_warning_errno(r, "Failed to set trusted sender for event storage: %m");

        uint64_t n = 0;
        for (;;) {
                r = fd_wait_for_event(sd_device_monitor_get_fd(storage), POLLIN, 0);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return log_warning_errno(r, "Failed to wait for event from event storage: %m");
                if (r == 0)
                        break;

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                r = sd_device_monitor_receive(storage, &dev);
                if (r < 0) {
                        log_warning_errno(r, "Failed to receive device from event storage, ignoring: %m");
                        continue;
                }

                r = event_queue_insert(manager, dev);
                if (r < 0) {
                        log_device_warning_errno(dev, r, "Failed to insert device into event queue, ignoring: %m");
                        continue;
                }

                n++;
        }

        log_debug("Deserialized %"PRIu64" events.", n);
        return 0;
}

static int on_uevent(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        DEVICE_TRACE_POINT(kernel_uevent_received, dev);

        device_ensure_usec_initialized(dev, NULL);

        r = event_queue_insert(manager, dev);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to insert device into event queue: %m");
                return 1;
        }

        (void) manager_requeue_locked_events_by_device(manager, dev);
        return 1;
}

static int manager_init_device_monitor(Manager *manager, int fd) {
        int r;

        assert(manager);

        /* This takes passed file descriptor on success. */

        if (fd >= 0) {
                if (manager->monitor)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple netlink socket (%i), ignoring.", fd);

                r = sd_is_socket(fd, AF_NETLINK, SOCK_RAW, /* listening = */ -1);
                if (r < 0)
                        return log_warning_errno(r, "Failed to verify socket type of %i, ignoring: %m", fd);
                if (r == 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Received invalid netlink socket (%i), ignoring.", fd);
        } else {
                if (manager->monitor)
                        return 0;
        }

        r = device_monitor_new_full(&manager->monitor, MONITOR_GROUP_KERNEL, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        return 0;
}

static int manager_start_device_monitor(Manager *manager) {
        int r;

        assert(manager);

        r = manager_init_device_monitor(manager, -EBADF);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(manager->monitor, "manager");

        r = sd_device_monitor_attach_event(manager->monitor, manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(manager->monitor, on_uevent, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        r = sd_event_source_set_priority(sd_device_monitor_get_event_source(manager->monitor), EVENT_PRIORITY_DEVICE_MONITOR);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority to device monitor: %m");

        return 0;
}

static int on_worker_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_(pidref_done) PidRef sender = PIDREF_NULL;
        _cleanup_strv_free_ char **l = NULL;
        r = notify_recv_strv(fd, &l, /* ret_ucred= */ NULL, &sender);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        /* lookup worker who sent the signal */
        Worker *worker = hashmap_get(manager->workers, &sender);
        if (!worker) {
                log_warning("Received notify datagram of unknown process ["PID_FMT"], ignoring.", sender.pid);
                return 0;
        }

        if (strv_contains(l, "INOTIFY_WATCH_ADD=1")) {
                assert(worker->event);

                r = manager_add_watch(manager, worker->event->dev);
                if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        r = 0;
                if (r < 0)
                        log_device_warning_errno(worker->event->dev, r, "Failed to add inotify watch, ignoring: %m");

                /* Send the result back to the worker process. */
                r = pidref_sigqueue(&sender, SIGUSR1, r);
                if (r < 0) {
                        log_device_warning_errno(worker->event->dev, r,
                                                 "Failed to send signal to worker process ["PID_FMT"], killing the worker process: %m",
                                                 sender.pid);

                        (void) pidref_kill(&sender, SIGTERM);
                        worker->state = WORKER_KILLED;
                }
                return 0;
        }

        if (strv_contains(l, "INOTIFY_WATCH_REMOVE=1")) {
                assert(worker->event);

                r = manager_remove_watch(manager, worker->event->dev);
                if (r < 0)
                        log_device_warning_errno(worker->event->dev, r, "Failed to remove inotify watch, ignoring: %m");

                /* Send the result back to the worker process. */
                r = pidref_sigqueue(&sender, SIGUSR1, r);
                if (r < 0) {
                        log_device_warning_errno(worker->event->dev, r,
                                                 "Failed to send signal to worker process ["PID_FMT"], killing the worker process: %m",
                                                 sender.pid);

                        (void) pidref_kill(&sender, SIGTERM);
                        worker->state = WORKER_KILLED;
                }
                return 0;
        }

        _cleanup_(event_freep) Event *event = worker_detach_event(worker);

        if (strv_contains(l, "TRY_AGAIN=1")) {
                /* Worker cannot lock the device. */
                r = event_enter_locked(event, strv_find_startswith(l, "WHOLE_DISK="));
                if (r < 0) {
                        (void) device_add_errno(event->dev, r);
                        (void) device_broadcast_on_error(event->dev, manager->monitor);
                } else
                        TAKE_PTR(event);
        }

        return 0;
}

static int manager_start_worker_notify(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        r = notify_socket_prepare(
                        manager->event,
                        EVENT_PRIORITY_WORKER_NOTIFY,
                        on_worker_notify,
                        manager,
                        &manager->worker_notify_socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare worker notification socket: %m");

        return 0;
}

static int on_sigterm(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        manager_exit(manager);

        return 1;
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        manager_reload(manager, /* force = */ true);

        return 1;
}

static int manager_unlink_queue_file(Manager *manager) {
        assert(manager);

        if (manager->events)
                return 0; /* There are queued events. */

        if (!set_isempty(manager->synthesize_change_child_event_sources))
                return 0; /* There are child processes that should trigger synthetic events. */

        /* There are no queued events. Let's remove /run/udev/queue and clean up the idle processes. */
        if (unlink("/run/udev/queue") < 0) {
                if (errno != ENOENT)
                        return log_warning_errno(errno, "Failed to unlink /run/udev/queue: %m");
        } else
                log_debug("No events are queued, removed /run/udev/queue.");

        manager->queue_file_created = false;
        return 0;
}

static int on_post_exit(Manager *manager) {
        assert(manager);
        assert(manager->exit);

        LIST_FOREACH(event, event, manager->events)
                if (event->state == EVENT_RUNNING)
                        return 0; /* There still exist events being processed. */

        (void) manager_unlink_queue_file(manager);

        if (!hashmap_isempty(manager->workers))
                return 0; /* There still exist running workers. */

        (void) manager_serialize_events(manager);

        udev_watch_dump();
        return sd_event_exit(manager->event, 0);
}

static int on_post(sd_event_source *s, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        if (manager->exit)
                return on_post_exit(manager);

        if (manager->events) {
                (void) manager_requeue_locked_events(manager);

                /* Try to process pending events if idle workers exist. Why is this necessary?
                 * When a worker finished an event and became idle, even if there was a pending event,
                 * the corresponding device might have been locked and the processing of the event
                 * delayed for a while, preventing the worker from processing the event immediately.
                 * Now, the device may be unlocked. Let's try again! */
                (void) event_queue_start(manager);
                return 0;
        }

        (void) manager_unlink_queue_file(manager);
        (void) manager_reset_kill_workers_timer(manager);

        if (!hashmap_isempty(manager->workers))
                return 0; /* There still exist idle workers. */

        if (manager->cgroup && set_isempty(manager->synthesize_change_child_event_sources))
                /* cleanup possible left-over processes in our cgroup */
                (void) cg_kill(manager->cgroup, SIGKILL, CGROUP_IGNORE_SELF, /* killed_pids=*/ NULL, /* log_kill= */ NULL, /* userdata= */ NULL);

        return 0;
}

static int manager_setup_signal(
                Manager *manager,
                sd_event *event,
                int signal,
                sd_event_signal_handler_t handler,
                int64_t priority,
                const char *description) {

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(manager);
        assert(event);

        r = sd_event_add_signal(event, &s, signal | SD_EVENT_SIGNAL_PROCMASK, handler, manager);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, priority);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, description);

        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return r;

        return 0;
}

static int manager_setup_event(Manager *manager) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r;

        assert(manager);

        /* block SIGCHLD for listening child events. */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);

        r = sd_event_default(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = manager_setup_signal(manager, e, SIGINT, on_sigterm, EVENT_PRIORITY_SIGTERM, "sigint-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGINT event source: %m");

        r = manager_setup_signal(manager, e, SIGTERM, on_sigterm, EVENT_PRIORITY_SIGTERM, "sigterm-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGTERM event source: %m");

        r = manager_setup_signal(manager, e, SIGHUP, on_sighup, EVENT_PRIORITY_SIGHUP, "sighup-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGHUP event source: %m");

        r = sd_event_add_post(e, /* ret = */ NULL, on_post, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create post event source: %m");

        /* Eventually, we probably want to do more here on memory pressure, for example, kill idle workers immediately */
        r = sd_event_add_memory_pressure(e, /* ret= */ NULL, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to allocate memory pressure watch, ignoring: %m");

        r = sd_event_add_signal(e, /* ret= */ NULL,
                                (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate SIGRTMIN+18 event source, ignoring: %m");

        r = sd_event_set_watchdog(e, true);
        if (r < 0)
                return log_error_errno(r, "Failed to create watchdog event source: %m");

        manager->event = TAKE_PTR(e);
        return 0;
}

static int manager_listen_fds(Manager *manager, int *ret_varlink_fd) {
        _cleanup_strv_free_ char **names = NULL;
        int varlink_fd = -EBADF;
        int r;

        assert(manager);
        assert(ret_varlink_fd);

        int n = sd_listen_fds_with_names(/* unset_environment = */ true, &names);
        if (n < 0)
                return log_error_errno(n, "Failed to listen on fds: %m");

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;

                if (streq(names[i], "varlink")) {
                        varlink_fd = fd;
                        r = 0;
                } else if (streq(names[i], "systemd-udevd-control.socket"))
                        r = manager_init_ctrl(manager, fd);
                else if (streq(names[i], "systemd-udevd-kernel.socket"))
                        r = manager_init_device_monitor(manager, fd);
                else if (streq(names[i], "inotify"))
                        r = manager_init_inotify(manager, fd);
                else if (streq(names[i], "config-serialization"))
                        r = manager_deserialize_config(manager, &fd);
                else if (streq(names[i], "event-serialization"))
                        r = manager_deserialize_events(manager, &fd);
                else
                        r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                            "Received unexpected fd (%s), ignoring.", names[i]);
                if (r < 0)
                        close_and_notify_warn(fd, names[i]);
        }

        *ret_varlink_fd = varlink_fd;

        return 0;
}

int manager_main(Manager *manager) {
        _cleanup_close_ int varlink_fd = -EBADF;
        int r;

        assert(manager);

        _cleanup_free_ char *cgroup = NULL;
        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        if (r < 0)
                log_debug_errno(r, "Failed to get cgroup, ignoring: %m");
        else if (endswith(cgroup, "/udev")) { /* If we are in a subcgroup /udev/ we assume it was delegated to us */
                log_debug("Running in delegated subcgroup '%s'.", cgroup);
                manager->cgroup = TAKE_PTR(cgroup);
        }

        r = manager_setup_event(manager);
        if (r < 0)
                return r;

        r = manager_listen_fds(manager, &varlink_fd);
        if (r < 0)
                return r;

        r = manager_start_ctrl(manager);
        if (r < 0)
                return r;

        r = manager_start_varlink_server(manager, TAKE_FD(varlink_fd));
        if (r < 0)
                return r;

        r = manager_start_device_monitor(manager);
        if (r < 0)
                return r;

        r = manager_start_inotify(manager);
        if (r < 0)
                return r;

        r = manager_start_worker_notify(manager);
        if (r < 0)
                return r;

        manager->last_usec = now(CLOCK_MONOTONIC);

        udev_builtin_init();

        r = udev_rules_load(&manager->rules, manager->config.resolve_name_timing, /* extra = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read udev rules: %m");

        r = udev_rules_apply_static_dev_perms(manager->rules);
        if (r < 0)
                log_warning_errno(r, "Failed to apply permissions on static device nodes, ignoring: %m");

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message =
                notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        /* We will start processing events in the loop below. Before starting processing, let's remove the
         * event serialization fd from the fdstore, to avoid retrieving the serialized events again in future
         * invocations. Otherwise, the serialized events may be processed multiple times. */
        (void) notify_remove_fd("event-serialization");

        r = sd_event_loop(manager->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
