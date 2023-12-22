/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "blockdev-util.h"
#include "cgroup-util.h"
#include "common-signal.h"
#include "cpu-set-util.h"
#include "daemon-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-list.h"
#include "event-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "inotify-util.h"
#include "iovec-util.h"
#include "limits-util.h"
#include "list.h"
#include "mkdir.h"
#include "process-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "udev-builtin.h"
#include "udev-ctrl.h"
#include "udev-event.h"
#include "udev-manager.h"
#include "udev-node.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-watch.h"
#include "udev-worker.h"

#define WORKER_NUM_MAX UINT64_C(2048)

#define EVENT_RETRY_INTERVAL_USEC (200 * USEC_PER_MSEC)
#define EVENT_RETRY_TIMEOUT_USEC  (3 * USEC_PER_MINUTE)

typedef enum EventState {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
} EventState;

typedef struct Event {
        Manager *manager;
        Worker *worker;
        EventState state;

        sd_device *dev;

        sd_device_action_t action;
        uint64_t seqnum;
        uint64_t blocker_seqnum;
        const char *id;
        const char *devpath;
        const char *devpath_old;
        const char *devnode;

        /* Used when the device is locked by another program. */
        usec_t retry_again_next_usec;
        usec_t retry_again_timeout_usec;
        sd_event_source *retry_event_source;

        sd_event_source *timeout_warning_event;
        sd_event_source *timeout_event;

        LIST_FIELDS(Event, event);
} Event;

typedef enum WorkerState {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
        WORKER_KILLING,
} WorkerState;

typedef struct Worker {
        Manager *manager;
        pid_t pid;
        sd_event_source *child_event_source;
        sd_device_monitor *monitor;
        WorkerState state;
        Event *event;
} Worker;

static Event *event_free(Event *event) {
        if (!event)
                return NULL;

        assert(event->manager);

        LIST_REMOVE(event, event->manager->events, event);
        sd_device_unref(event->dev);

        sd_event_source_unref(event->retry_event_source);
        sd_event_source_unref(event->timeout_warning_event);
        sd_event_source_unref(event->timeout_event);

        if (event->worker)
                event->worker->event = NULL;

        return mfree(event);
}

static void event_queue_cleanup(Manager *manager, EventState match_state) {
        LIST_FOREACH(event, event, manager->events) {
                if (match_state != EVENT_UNDEF && match_state != event->state)
                        continue;

                event_free(event);
        }
}

static Worker *worker_free(Worker *worker) {
        if (!worker)
                return NULL;

        if (worker->manager)
                hashmap_remove(worker->manager->workers, PID_TO_PTR(worker->pid));

        sd_event_source_unref(worker->child_event_source);
        sd_device_monitor_unref(worker->monitor);
        event_free(worker->event);

        return mfree(worker);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Worker*, worker_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(worker_hash_op, void, trivial_hash_func, trivial_compare_func, Worker, worker_free);

Manager* manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        udev_builtin_exit();

        hashmap_free_free_free(manager->properties);
        udev_rules_free(manager->rules);

        hashmap_free(manager->workers);
        event_queue_cleanup(manager, EVENT_UNDEF);

        safe_close(manager->inotify_fd);
        safe_close_pair(manager->worker_watch);

        sd_device_monitor_unref(manager->monitor);
        udev_ctrl_unref(manager->ctrl);

        sd_event_source_unref(manager->inotify_event);
        sd_event_source_unref(manager->kill_workers_event);
        sd_event_source_unref(manager->memory_pressure_event_source);
        sd_event_source_unref(manager->sigrtmin18_event_source);
        sd_event_unref(manager->event);

        free(manager->cgroup);
        return mfree(manager);
}

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata);

static int worker_new(Worker **ret, Manager *manager, sd_device_monitor *worker_monitor, pid_t pid) {
        _cleanup_(worker_freep) Worker *worker = NULL;
        int r;

        assert(ret);
        assert(manager);
        assert(worker_monitor);
        assert(pid > 1);

        /* close monitor, but keep address around */
        device_monitor_disconnect(worker_monitor);

        worker = new(Worker, 1);
        if (!worker)
                return -ENOMEM;

        *worker = (Worker) {
                .monitor = sd_device_monitor_ref(worker_monitor),
                .pid = pid,
        };

        r = sd_event_add_child(manager->event, &worker->child_event_source, pid, WEXITED, on_sigchld, worker);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&manager->workers, &worker_hash_op, PID_TO_PTR(pid), worker);
        if (r < 0)
                return r;

        worker->manager = manager;

        *ret = TAKE_PTR(worker);
        return 0;
}

static void manager_kill_workers(Manager *manager, bool force) {
        Worker *worker;

        assert(manager);

        HASHMAP_FOREACH(worker, manager->workers) {
                if (worker->state == WORKER_KILLED)
                        continue;

                if (worker->state == WORKER_RUNNING && !force) {
                        worker->state = WORKER_KILLING;
                        continue;
                }

                worker->state = WORKER_KILLED;
                (void) kill(worker->pid, SIGTERM);
        }
}

static void manager_exit(Manager *manager) {
        assert(manager);

        manager->exit = true;

        (void) sd_notify(/* unset= */ false, NOTIFY_STOPPING);

        /* close sources of new events and discard buffered events */
        manager->ctrl = udev_ctrl_unref(manager->ctrl);

        manager->inotify_event = sd_event_source_disable_unref(manager->inotify_event);
        manager->inotify_fd = safe_close(manager->inotify_fd);

        manager->monitor = sd_device_monitor_unref(manager->monitor);

        /* discard queued events and kill workers */
        event_queue_cleanup(manager, EVENT_QUEUED);
        manager_kill_workers(manager, true);
}

static void notify_ready(Manager *manager) {
        int r;

        assert(manager);

        r = sd_notifyf(/* unset= */ false,
                       "READY=1\n"
                       "STATUS=Processing with %u children at max", manager->children_max);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
}

/* reload requested, HUP signal received, rules changed, builtin changed */
static void manager_reload(Manager *manager, bool force) {
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

        /* Nothing changed. It is not necessary to reload. */
        if (!udev_rules_should_reload(manager->rules) && !udev_builtin_should_reload()) {

                if (!force)
                        return;

                /* If we eat this up, then tell our service manager to just continue */
                (void) sd_notifyf(/* unset= */ false,
                                  "RELOADING=1\n"
                                  "STATUS=Skipping configuration reloading, nothing changed.\n"
                                  "MONOTONIC_USEC=" USEC_FMT, now(CLOCK_MONOTONIC));
        } else {
                (void) sd_notifyf(/* unset= */ false,
                                  "RELOADING=1\n"
                                  "STATUS=Flushing configuration...\n"
                                  "MONOTONIC_USEC=" USEC_FMT, now(CLOCK_MONOTONIC));

                manager_kill_workers(manager, false);

                udev_builtin_exit();
                udev_builtin_init();

                r = udev_rules_load(&rules, manager->resolve_name_timing);
                if (r < 0)
                        log_warning_errno(r, "Failed to read udev rules, using the previously loaded rules, ignoring: %m");
                else
                        udev_rules_free_and_replace(manager->rules, rules);
        }

        notify_ready(manager);
}

static int on_kill_workers_event(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        log_debug("Cleanup idle workers");
        manager_kill_workers(manager, false);

        return 1;
}

static int on_event_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Event *event = ASSERT_PTR(userdata);

        assert(event->manager);
        assert(event->worker);

        kill_and_sigcont(event->worker->pid, event->manager->timeout_signal);
        event->worker->state = WORKER_KILLED;

        log_device_error(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" killed", event->worker->pid, event->seqnum);

        return 1;
}

static int on_event_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Event *event = ASSERT_PTR(userdata);

        assert(event->worker);

        log_device_warning(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" is taking a long time", event->worker->pid, event->seqnum);

        return 1;
}

static void worker_attach_event(Worker *worker, Event *event) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(worker)->manager);
        sd_event *e = ASSERT_PTR(manager->event);

        assert(event);
        assert(!event->worker);
        assert(!worker->event);

        worker->state = WORKER_RUNNING;
        worker->event = event;
        event->state = EVENT_RUNNING;
        event->worker = worker;

        (void) sd_event_add_time_relative(e, &event->timeout_warning_event, CLOCK_MONOTONIC,
                                          udev_warn_timeout(manager->timeout_usec), USEC_PER_SEC,
                                          on_event_timeout_warning, event);

        (void) sd_event_add_time_relative(e, &event->timeout_event, CLOCK_MONOTONIC,
                                          manager->timeout_usec, USEC_PER_SEC,
                                          on_event_timeout, event);
}

static int worker_spawn(Manager *manager, Event *event) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *worker_monitor = NULL;
        Worker *worker;
        pid_t pid;
        int r;

        /* listen for new events */
        r = device_monitor_new_full(&worker_monitor, MONITOR_GROUP_NONE, -1);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(worker_monitor, "worker");

        /* allow the main daemon netlink address to send devices to the worker */
        r = device_monitor_allow_unicast_sender(worker_monitor, manager->monitor);
        if (r < 0)
                return log_error_errno(r, "Worker: Failed to set unicast sender: %m");

        r = device_monitor_enable_receiving(worker_monitor);
        if (r < 0)
                return log_error_errno(r, "Worker: Failed to enable receiving of device: %m");

        r = safe_fork("(udev-worker)", FORK_DEATHSIG_SIGTERM, &pid);
        if (r < 0) {
                event->state = EVENT_QUEUED;
                return log_error_errno(r, "Failed to fork() worker: %m");
        }
        if (r == 0) {
                _cleanup_(udev_worker_done) UdevWorker w = {
                        .monitor = TAKE_PTR(worker_monitor),
                        .properties = TAKE_PTR(manager->properties),
                        .rules = TAKE_PTR(manager->rules),
                        .pipe_fd = TAKE_FD(manager->worker_watch[WRITE_END]),
                        .inotify_fd = TAKE_FD(manager->inotify_fd),
                        .exec_delay_usec = manager->exec_delay_usec,
                        .timeout_usec = manager->timeout_usec,
                        .timeout_signal = manager->timeout_signal,
                        .log_level = manager->log_level,
                        .blockdev_read_only = manager->blockdev_read_only,
                };

                /* Worker process */
                r = udev_worker_main(&w, event->dev);
                log_close();
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        r = worker_new(&worker, manager, worker_monitor, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to create worker object: %m");

        worker_attach_event(worker, event);

        log_device_debug(event->dev, "Worker ["PID_FMT"] is forked for processing SEQNUM=%"PRIu64".", pid, event->seqnum);
        return 0;
}

static int event_run(Event *event) {
        static bool log_children_max_reached = true;
        Manager *manager;
        Worker *worker;
        int r;

        assert(event);
        assert(event->manager);

        log_device_uevent(event->dev, "Device ready for processing");

        (void) event_source_disable(event->retry_event_source);

        manager = event->manager;
        HASHMAP_FOREACH(worker, manager->workers) {
                if (worker->state != WORKER_IDLE)
                        continue;

                r = device_monitor_send_device(manager->monitor, worker->monitor, event->dev);
                if (r < 0) {
                        log_device_error_errno(event->dev, r, "Worker ["PID_FMT"] did not accept message, killing the worker: %m",
                                               worker->pid);
                        (void) kill(worker->pid, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_attach_event(worker, event);
                return 1; /* event is now processing. */
        }

        if (hashmap_size(manager->workers) >= manager->children_max) {
                /* Avoid spamming the debug logs if the limit is already reached and
                 * many events still need to be processed */
                if (log_children_max_reached && manager->children_max > 1) {
                        log_debug("Maximum number (%u) of children reached.", hashmap_size(manager->workers));
                        log_children_max_reached = false;
                }
                return 0; /* no free worker */
        }

        /* Re-enable the debug message for the next batch of events */
        log_children_max_reached = true;

        /* start new worker and pass initial device */
        r = worker_spawn(manager, event);
        if (r < 0)
                return r;

        return 1; /* event is now processing. */
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

static int event_is_blocked(Event *event) {
        Event *loop_event = NULL;
        int r;

        /* lookup event for identical, parent, child device */

        assert(event);
        assert(event->manager);
        assert(event->blocker_seqnum <= event->seqnum);

        if (event->retry_again_next_usec > 0) {
                usec_t now_usec;

                r = sd_event_now(event->manager->event, CLOCK_BOOTTIME, &now_usec);
                if (r < 0)
                        return r;

                if (event->retry_again_next_usec > now_usec)
                        return true;
        }

        if (event->blocker_seqnum == event->seqnum)
                /* we have checked previously and no blocker found */
                return false;

        LIST_FOREACH(event, e, event->manager->events) {
                loop_event = e;

                /* we already found a later event, earlier cannot block us, no need to check again */
                if (loop_event->seqnum < event->blocker_seqnum)
                        continue;

                /* event we checked earlier still exists, no need to check again */
                if (loop_event->seqnum == event->blocker_seqnum)
                        return true;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        goto no_blocker;

                /* found event we have not checked */
                break;
        }

        assert(loop_event);
        assert(loop_event->seqnum > event->blocker_seqnum &&
               loop_event->seqnum < event->seqnum);

        /* check if queue contains events we depend on */
        LIST_FOREACH(event, e, loop_event) {
                loop_event = e;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        goto no_blocker;

                if (streq_ptr(loop_event->id, event->id))
                        break;

                if (devpath_conflict(event->devpath, loop_event->devpath) ||
                    devpath_conflict(event->devpath, loop_event->devpath_old) ||
                    devpath_conflict(event->devpath_old, loop_event->devpath))
                        break;

                if (event->devnode && streq_ptr(event->devnode, loop_event->devnode))
                        break;
        }

        assert(loop_event);

        log_device_debug(event->dev, "SEQNUM=%" PRIu64 " blocked by SEQNUM=%" PRIu64,
                         event->seqnum, loop_event->seqnum);

        event->blocker_seqnum = loop_event->seqnum;
        return true;

no_blocker:
        event->blocker_seqnum = event->seqnum;
        return false;
}

static int event_queue_start(Manager *manager) {
        int r;

        assert(manager);

        if (!manager->events || manager->exit || manager->stop_exec_queue)
                return 0;

        /* To make the stack directory /run/udev/links cleaned up later. */
        manager->udev_node_needs_cleanup = true;

        r = event_source_disable(manager->kill_workers_event);
        if (r < 0)
                log_warning_errno(r, "Failed to disable event source for cleaning up idle workers, ignoring: %m");

        manager_reload(manager, /* force = */ false);

        LIST_FOREACH(event, event, manager->events) {
                if (event->state != EVENT_QUEUED)
                        continue;

                /* do not start event if parent or child event is still running or queued */
                r = event_is_blocked(event);
                if (r > 0)
                        continue;
                if (r < 0)
                        log_device_warning_errno(event->dev, r,
                                                 "Failed to check dependencies for event (SEQNUM=%"PRIu64", ACTION=%s), "
                                                 "assuming there is no blocking event, ignoring: %m",
                                                 event->seqnum,
                                                 strna(device_action_to_string(event->action)));

                r = event_run(event);
                if (r <= 0) /* 0 means there are no idle workers. Let's escape from the loop. */
                        return r;
        }

        return 0;
}

static int on_event_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        /* This does nothing. The on_post() callback will start the event if there exists an idle worker. */
        return 1;
}

static int event_requeue(Event *event) {
        usec_t now_usec;
        int r;

        assert(event);
        assert(event->manager);
        assert(event->manager->event);

        event->timeout_warning_event = sd_event_source_disable_unref(event->timeout_warning_event);
        event->timeout_event = sd_event_source_disable_unref(event->timeout_event);

        /* add a short delay to suppress busy loop */
        r = sd_event_now(event->manager->event, CLOCK_BOOTTIME, &now_usec);
        if (r < 0)
                return log_device_warning_errno(event->dev, r,
                                                "Failed to get current time, "
                                                "skipping event (SEQNUM=%"PRIu64", ACTION=%s): %m",
                                                event->seqnum, strna(device_action_to_string(event->action)));

        if (event->retry_again_timeout_usec > 0 && event->retry_again_timeout_usec <= now_usec)
                return log_device_warning_errno(event->dev, SYNTHETIC_ERRNO(ETIMEDOUT),
                                                "The underlying block device is locked by a process more than %s, "
                                                "skipping event (SEQNUM=%"PRIu64", ACTION=%s).",
                                                FORMAT_TIMESPAN(EVENT_RETRY_TIMEOUT_USEC, USEC_PER_MINUTE),
                                                event->seqnum, strna(device_action_to_string(event->action)));

        event->retry_again_next_usec = usec_add(now_usec, EVENT_RETRY_INTERVAL_USEC);
        if (event->retry_again_timeout_usec == 0)
                event->retry_again_timeout_usec = usec_add(now_usec, EVENT_RETRY_TIMEOUT_USEC);

        r = event_reset_time_relative(event->manager->event, &event->retry_event_source,
                                      CLOCK_MONOTONIC, EVENT_RETRY_INTERVAL_USEC, 0,
                                      on_event_retry, NULL,
                                      0, "retry-event", true);
        if (r < 0)
                return log_device_warning_errno(event->dev, r, "Failed to reset timer event source for retrying event, "
                                                "skipping event (SEQNUM=%"PRIu64", ACTION=%s): %m",
                                                event->seqnum, strna(device_action_to_string(event->action)));

        if (event->worker && event->worker->event == event)
                event->worker->event = NULL;
        event->worker = NULL;

        event->state = EVENT_QUEUED;
        return 0;
}

static int event_queue_assume_block_device_unlocked(Manager *manager, sd_device *dev) {
        const char *devname;
        int r;

        /* When a new event for a block device is queued or we get an inotify event, assume that the
         * device is not locked anymore. The assumption may not be true, but that should not cause any
         * issues, as in that case events will be requeued soon. */

        r = udev_get_whole_disk(dev, NULL, &devname);
        if (r <= 0)
                return r;

        LIST_FOREACH(event, event, manager->events) {
                const char *event_devname;

                if (event->state != EVENT_QUEUED)
                        continue;

                if (event->retry_again_next_usec == 0)
                        continue;

                if (udev_get_whole_disk(event->dev, NULL, &event_devname) <= 0)
                        continue;

                if (!streq(devname, event_devname))
                        continue;

                event->retry_again_next_usec = 0;
        }

        return 0;
}

static int event_queue_insert(Manager *manager, sd_device *dev) {
        const char *devpath, *devpath_old = NULL, *id = NULL, *devnode = NULL;
        sd_device_action_t action;
        uint64_t seqnum;
        Event *event;
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

        r = device_get_device_id(dev, &id);
        if (r < 0 && r != -ENOENT)
                return r;

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0 && r != -ENOENT)
                return r;

        event = new(Event, 1);
        if (!event)
                return -ENOMEM;

        *event = (Event) {
                .manager = manager,
                .dev = sd_device_ref(dev),
                .seqnum = seqnum,
                .action = action,
                .id = id,
                .devpath = devpath,
                .devpath_old = devpath_old,
                .devnode = devnode,
                .state = EVENT_QUEUED,
        };

        if (!manager->events) {
                r = touch("/run/udev/queue");
                if (r < 0)
                        log_warning_errno(r, "Failed to touch /run/udev/queue, ignoring: %m");
        }

        LIST_APPEND(event, manager->events, event);

        log_device_uevent(dev, "Device is queued");

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

        (void) event_queue_assume_block_device_unlocked(manager, dev);

        return 1;
}

static int on_worker(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        for (;;) {
                EventResult result;
                struct iovec iovec = IOVEC_MAKE(&result, sizeof(result));
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };
                ssize_t size;
                struct ucred *ucred;
                Worker *worker;

                size = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT);
                if (size == -EINTR)
                        continue;
                if (size == -EAGAIN)
                        /* nothing more to read */
                        break;
                if (size < 0)
                        return log_error_errno(size, "Failed to receive message: %m");

                cmsg_close_all(&msghdr);

                if (size != sizeof(result)) {
                        log_warning("Ignoring worker message with invalid size %zi bytes", size);
                        continue;
                }

                ucred = CMSG_FIND_DATA(&msghdr, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
                if (!ucred || ucred->pid <= 0) {
                        log_warning("Ignoring worker message without valid PID");
                        continue;
                }

                /* lookup worker who sent the signal */
                worker = hashmap_get(manager->workers, PID_TO_PTR(ucred->pid));
                if (!worker) {
                        log_debug("Worker ["PID_FMT"] returned, but is no longer tracked", ucred->pid);
                        continue;
                }

                if (worker->state == WORKER_KILLING) {
                        worker->state = WORKER_KILLED;
                        (void) kill(worker->pid, SIGTERM);
                } else if (worker->state != WORKER_KILLED)
                        worker->state = WORKER_IDLE;

                /* worker returned */
                if (result == EVENT_RESULT_TRY_AGAIN &&
                    event_requeue(worker->event) < 0)
                        udev_broadcast_result(manager->monitor, worker->event->dev, -ETIMEDOUT);

                /* When event_requeue() succeeds, worker->event is NULL, and event_free() handles NULL gracefully. */
                event_free(worker->event);
        }

        return 1;
}

static void manager_set_default_children_max(Manager *manager) {
        uint64_t cpu_limit, mem_limit, cpu_count = 1;
        int r;

        assert(manager);

        if (manager->children_max != 0)
                return;

        r = cpus_in_affinity_mask();
        if (r < 0)
                log_warning_errno(r, "Failed to determine number of local CPUs, ignoring: %m");
        else
                cpu_count = r;

        cpu_limit = cpu_count * 2 + 16;
        mem_limit = MAX(physical_memory() / (128*1024*1024), UINT64_C(10));

        manager->children_max = MIN3(cpu_limit, mem_limit, WORKER_NUM_MAX);
        log_debug("Set children_max to %u", manager->children_max);
}

/* receive the udevd message from userspace */
static int on_ctrl_msg(UdevCtrl *uctrl, UdevCtrlMessageType type, const UdevCtrlMessageValue *value, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(value);

        switch (type) {
        case UDEV_CTRL_SET_LOG_LEVEL:
                if ((value->intval & LOG_PRIMASK) != value->intval) {
                        log_debug("Received invalid udev control message (SET_LOG_LEVEL, %i), ignoring.", value->intval);
                        break;
                }

                log_debug("Received udev control message (SET_LOG_LEVEL), setting log_level=%i", value->intval);

                r = log_get_max_level();
                if (r == value->intval)
                        break;

                log_set_max_level(value->intval);
                manager->log_level = value->intval;
                manager_kill_workers(manager, false);
                break;
        case UDEV_CTRL_STOP_EXEC_QUEUE:
                log_debug("Received udev control message (STOP_EXEC_QUEUE)");
                manager->stop_exec_queue = true;
                break;
        case UDEV_CTRL_START_EXEC_QUEUE:
                log_debug("Received udev control message (START_EXEC_QUEUE)");
                manager->stop_exec_queue = false;
                /* It is not necessary to call event_queue_start() here, as it will be called in on_post() if necessary. */
                break;
        case UDEV_CTRL_RELOAD:
                log_debug("Received udev control message (RELOAD)");
                manager_reload(manager, /* force = */ true);
                break;
        case UDEV_CTRL_SET_ENV: {
                _unused_ _cleanup_free_ char *old_val = NULL, *old_key = NULL;
                _cleanup_free_ char *key = NULL, *val = NULL;
                const char *eq;

                eq = strchr(value->buf, '=');
                if (!eq) {
                        log_error("Invalid key format '%s'", value->buf);
                        return 1;
                }

                key = strndup(value->buf, eq - value->buf);
                if (!key) {
                        log_oom();
                        return 1;
                }

                old_val = hashmap_remove2(manager->properties, key, (void **) &old_key);

                r = hashmap_ensure_allocated(&manager->properties, &string_hash_ops);
                if (r < 0) {
                        log_oom();
                        return 1;
                }

                eq++;
                if (isempty(eq))
                        log_debug("Received udev control message (ENV), unsetting '%s'", key);
                else {
                        val = strdup(eq);
                        if (!val) {
                                log_oom();
                                return 1;
                        }

                        log_debug("Received udev control message (ENV), setting '%s=%s'", key, val);

                        r = hashmap_put(manager->properties, key, val);
                        if (r < 0) {
                                log_oom();
                                return 1;
                        }
                }

                key = val = NULL;
                manager_kill_workers(manager, false);
                break;
        }
        case UDEV_CTRL_SET_CHILDREN_MAX:
                if (value->intval < 0) {
                        log_debug("Received invalid udev control message (SET_MAX_CHILDREN, %i), ignoring.", value->intval);
                        return 0;
                }

                log_debug("Received udev control message (SET_MAX_CHILDREN), setting children_max=%i", value->intval);
                manager->children_max = value->intval;

                /* When 0 is specified, determine the maximum based on the system resources. */
                manager_set_default_children_max(manager);

                notify_ready(manager);
                break;
        case UDEV_CTRL_PING:
                log_debug("Received udev control message (PING)");
                break;
        case UDEV_CTRL_EXIT:
                log_debug("Received udev control message (EXIT)");
                manager_exit(manager);
                break;
        default:
                log_debug("Received unknown udev control message, ignoring");
        }

        return 1;
}

static int synthesize_change_one(sd_device *dev, sd_device *target) {
        int r;

        if (DEBUG_LOGGING) {
                const char *syspath = NULL;
                (void) sd_device_get_syspath(target, &syspath);
                log_device_debug(dev, "device is closed, synthesising 'change' on %s", strna(syspath));
        }

        r = sd_device_trigger(target, SD_DEVICE_CHANGE);
        if (r < 0)
                return log_device_debug_errno(target, r, "Failed to trigger 'change' uevent: %m");

        DEVICE_TRACE_POINT(synthetic_change_event, dev);

        return 0;
}

static int synthesize_change(sd_device *dev) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool part_table_read;
        const char *sysname;
        int r, k;

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return r;

        if (startswith(sysname, "dm-") || block_device_is_whole_disk(dev) <= 0)
                return synthesize_change_one(dev, dev);

        r = blockdev_reread_partition_table(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to re-read partition table, ignoring: %m");
        part_table_read = r >= 0;

        /* search for partitions */
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return r;

        /* We have partitions and re-read the table, the kernel already sent out a "change"
         * event for the disk, and "remove/add" for all partitions. */
        if (part_table_read && sd_device_enumerator_get_device_first(e))
                return 0;

        /* We have partitions but re-reading the partition table did not work, synthesize
         * "change" for the disk and all partitions. */
        r = synthesize_change_one(dev, dev);
        FOREACH_DEVICE(e, d) {
                k = synthesize_change_one(dev, d);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        union inotify_event_buffer buffer;
        ssize_t l;
        int r;

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read inotify fd: %m");
        }

        FOREACH_INOTIFY_EVENT_WARN(e, buffer, l) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                const char *devnode;

                /* Do not handle IN_IGNORED here. Especially, do not try to call udev_watch_end() from the
                 * main process. Otherwise, the pair of the symlinks may become inconsistent, and several
                 * garbage may remain. The old symlinks are removed by a worker that processes the
                 * corresponding 'remove' uevent;
                 * udev_event_execute_rules() -> event_execute_rules_on_remove() -> udev_watch_end(). */

                if (!FLAGS_SET(e->mask, IN_CLOSE_WRITE))
                        continue;

                r = device_new_from_watch_handle(&dev, e->wd);
                if (r < 0) {
                        /* Device may be removed just after closed. */
                        log_debug_errno(r, "Failed to create sd_device object from watch handle, ignoring: %m");
                        continue;
                }

                r = sd_device_get_devname(dev, &devnode);
                if (r < 0) {
                        /* Also here, device may be already removed. */
                        log_device_debug_errno(dev, r, "Failed to get device node, ignoring: %m");
                        continue;
                }

                log_device_debug(dev, "Received inotify event for %s.", devnode);

                (void) event_queue_assume_block_device_unlocked(manager, dev);
                (void) synthesize_change(dev);
        }

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

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Worker *worker = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(worker->manager);
        sd_device *dev = worker->event ? ASSERT_PTR(worker->event->dev) : NULL;
        EventResult result;

        assert(si);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0)
                        log_device_debug(dev, "Worker ["PID_FMT"] exited.", si->si_pid);
                else
                        log_device_warning(dev, "Worker ["PID_FMT"] exited with return code %i.",
                                           si->si_pid, si->si_status);
                result = EVENT_RESULT_EXIT_STATUS_BASE + si->si_status;
                break;

        case CLD_KILLED:
        case CLD_DUMPED:
                log_device_warning(dev, "Worker ["PID_FMT"] terminated by signal %i (%s).",
                                   si->si_pid, si->si_status, signal_to_string(si->si_status));
                result = EVENT_RESULT_SIGNAL_BASE + si->si_status;
                break;

        default:
                assert_not_reached();
        }

        if (result != EVENT_RESULT_SUCCESS && dev) {
                /* delete state from disk */
                device_delete_db(dev);
                device_tag_index(dev, NULL, false);

                /* Forward kernel event to libudev listeners */
                udev_broadcast_result(manager->monitor, dev, result);
        }

        worker_free(worker);

        return 1;
}

static int on_post(sd_event_source *s, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        if (manager->events) {
                /* Try to process pending events if idle workers exist. Why is this necessary?
                 * When a worker finished an event and became idle, even if there was a pending event,
                 * the corresponding device might have been locked and the processing of the event
                 * delayed for a while, preventing the worker from processing the event immediately.
                 * Now, the device may be unlocked. Let's try again! */
                event_queue_start(manager);
                return 1;
        }

        /* There are no queued events. Let's remove /run/udev/queue and clean up the idle processes. */

        if (unlink("/run/udev/queue") < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to unlink /run/udev/queue, ignoring: %m");
        } else
                log_debug("No events are queued, removing /run/udev/queue.");

        if (!hashmap_isempty(manager->workers)) {
                /* There are idle workers */
                (void) event_reset_time_relative(manager->event, &manager->kill_workers_event,
                                                 CLOCK_MONOTONIC, 3 * USEC_PER_SEC, USEC_PER_SEC,
                                                 on_kill_workers_event, manager,
                                                 0, "kill-workers-event", false);
                return 1;
        }

        /* There are no idle workers. */

        if (manager->udev_node_needs_cleanup) {
                (void) udev_node_cleanup();
                manager->udev_node_needs_cleanup = false;
        }

        if (manager->exit)
                return sd_event_exit(manager->event, 0);

        if (manager->cgroup)
                /* cleanup possible left-over processes in our cgroup */
                (void) cg_kill(manager->cgroup, SIGKILL, CGROUP_IGNORE_SELF, /* set=*/ NULL, /* kill_log= */ NULL, /* userdata= */ NULL);

        return 1;
}

Manager* manager_new(void) {
        Manager *manager;

        manager = new(Manager, 1);
        if (!manager)
                return NULL;

        *manager = (Manager) {
                .inotify_fd = -EBADF,
                .worker_watch = EBADF_PAIR,
                .log_level = LOG_INFO,
                .resolve_name_timing = RESOLVE_NAME_EARLY,
                .timeout_usec = DEFAULT_WORKER_TIMEOUT_USEC,
                .timeout_signal = SIGKILL,
        };

        return manager;
}

void manager_adjust_arguments(Manager *manager) {
        assert(manager);

        if (manager->timeout_usec < MIN_WORKER_TIMEOUT_USEC) {
                log_debug("Timeout (%s) for processing event is too small, using the default: %s",
                          FORMAT_TIMESPAN(manager->timeout_usec, 1),
                          FORMAT_TIMESPAN(DEFAULT_WORKER_TIMEOUT_USEC, 1));

                manager->timeout_usec = DEFAULT_WORKER_TIMEOUT_USEC;
        }

        if (manager->exec_delay_usec >= manager->timeout_usec) {
                log_debug("Delay (%s) for executing RUN= commands is too large compared with the timeout (%s) for event execution, ignoring the delay.",
                          FORMAT_TIMESPAN(manager->exec_delay_usec, 1),
                          FORMAT_TIMESPAN(manager->timeout_usec, 1));

                manager->exec_delay_usec = 0;
        }
}

int manager_init(Manager *manager, int fd_ctrl, int fd_uevent) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(manager);

        r = udev_ctrl_new_from_fd(&manager->ctrl, fd_ctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev control socket: %m");

        r = udev_ctrl_enable_receiving(manager->ctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to bind udev control socket: %m");

        r = device_monitor_new_full(&manager->monitor, MONITOR_GROUP_KERNEL, fd_uevent);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        (void) sd_device_monitor_set_description(manager->monitor, "manager");

        r = device_monitor_enable_receiving(manager->monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to bind netlink socket: %m");

        manager->log_level = log_get_max_level();

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        if (r < 0)
                log_debug_errno(r, "Failed to get cgroup, ignoring: %m");
        else if (endswith(cgroup, "/udev")) { /* If we are in a subcgroup /udev/ we assume it was delegated to us */
                log_debug("Running in delegated subcgroup '%s'.", cgroup);
                manager->cgroup = TAKE_PTR(cgroup);
        }

        return 0;
}

int manager_main(Manager *manager) {
        int fd_worker, r;

        manager_set_default_children_max(manager);

        /* unnamed socket from workers to the main daemon */
        r = socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, manager->worker_watch);
        if (r < 0)
                return log_error_errno(errno, "Failed to create socketpair for communicating with workers: %m");

        fd_worker = manager->worker_watch[READ_END];

        r = setsockopt_int(fd_worker, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SO_PASSCRED: %m");

        manager->inotify_fd = inotify_init1(IN_CLOEXEC);
        if (manager->inotify_fd < 0)
                return log_error_errno(errno, "Failed to create inotify descriptor: %m");

        udev_watch_restore(manager->inotify_fd);

        /* block and listen to all signals on signalfd */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, SIGRTMIN+18, -1) >= 0);

        r = sd_event_default(&manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGINT, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGINT event source: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGTERM, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGTERM event source: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGHUP, on_sighup, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGHUP event source: %m");

        r = sd_event_set_watchdog(manager->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to create watchdog event source: %m");

        r = udev_ctrl_attach_event(manager->ctrl, manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to udev control: %m");

        r = udev_ctrl_start(manager->ctrl, on_ctrl_msg, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to start udev control: %m");

        /* This needs to be after the inotify and uevent handling, to make sure
         * that the ping is send back after fully processing the pending uevents
         * (including the synthetic ones we may create due to inotify events).
         */
        r = sd_event_source_set_priority(udev_ctrl_get_event_source(manager->ctrl), SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to set IDLE event priority for udev control event source: %m");

        r = sd_event_add_io(manager->event, &manager->inotify_event, manager->inotify_fd, EPOLLIN, on_inotify, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create inotify event source: %m");

        r = sd_device_monitor_attach_event(manager->monitor, manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(manager->monitor, on_uevent, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        r = sd_event_add_io(manager->event, NULL, fd_worker, EPOLLIN, on_worker, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create worker event source: %m");

        r = sd_event_add_post(manager->event, NULL, on_post, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create post event source: %m");

        /* Eventually, we probably want to do more here on memory pressure, for example, kill idle workers immediately */
        r = sd_event_add_memory_pressure(manager->event, &manager->memory_pressure_event_source, NULL, NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to allocate memory pressure watch, ignoring: %m");

        r = sd_event_add_signal(manager->event, &manager->memory_pressure_event_source, SIGRTMIN+18, sigrtmin18_handler, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate SIGRTMIN+18 event source, ignoring: %m");

        manager->last_usec = now(CLOCK_MONOTONIC);

        udev_builtin_init();

        r = udev_rules_load(&manager->rules, manager->resolve_name_timing);
        if (r < 0)
                return log_error_errno(r, "Failed to read udev rules: %m");

        r = udev_rules_apply_static_dev_perms(manager->rules);
        if (r < 0)
                log_warning_errno(r, "Failed to apply permissions on static device nodes, ignoring: %m");

        notify_ready(manager);

        r = sd_event_loop(manager->event);
        if (r < 0)
                log_error_errno(r, "Event loop failed: %m");

        (void) sd_notify(/* unset= */ false, NOTIFY_STOPPING);
        return r;
}
