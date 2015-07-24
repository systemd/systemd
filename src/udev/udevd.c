/*
 * Copyright (C) 2004-2012 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "terminal-util.h"
#include "signal-util.h"
#include "event-util.h"
#include "netlink-util.h"
#include "cgroup-util.h"
#include "process-util.h"
#include "dev-setup.h"
#include "fileio.h"
#include "selinux-util.h"
#include "udev.h"
#include "udev-util.h"
#include "formats-util.h"
#include "hashmap.h"

static bool arg_debug = false;
static int arg_daemonize = false;
static int arg_resolve_names = 1;
static unsigned arg_children_max;
static int arg_exec_delay;
static usec_t arg_event_timeout_usec = 180 * USEC_PER_SEC;
static usec_t arg_event_timeout_warn_usec = 180 * USEC_PER_SEC / 3;

typedef struct Manager {
        struct udev *udev;
        sd_event *event;
        Hashmap *workers;
        struct udev_list_node events;
        const char *cgroup;
        pid_t pid; /* the process that originally allocated the manager object */

        struct udev_rules *rules;
        struct udev_list properties;

        struct udev_monitor *monitor;
        struct udev_ctrl *ctrl;
        struct udev_ctrl_connection *ctrl_conn_blocking;
        int fd_inotify;
        int worker_watch[2];

        sd_event_source *ctrl_event;
        sd_event_source *uevent_event;
        sd_event_source *inotify_event;

        usec_t last_usec;

        bool stop_exec_queue:1;
        bool exit:1;
} Manager;

enum event_state {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
};

struct event {
        struct udev_list_node node;
        Manager *manager;
        struct udev *udev;
        struct udev_device *dev;
        struct udev_device *dev_kernel;
        struct worker *worker;
        enum event_state state;
        unsigned long long int delaying_seqnum;
        unsigned long long int seqnum;
        const char *devpath;
        size_t devpath_len;
        const char *devpath_old;
        dev_t devnum;
        int ifindex;
        bool is_block;
        sd_event_source *timeout_warning;
        sd_event_source *timeout;
};

static inline struct event *node_to_event(struct udev_list_node *node) {
        return container_of(node, struct event, node);
}

static void event_queue_cleanup(Manager *manager, enum event_state type);

enum worker_state {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
};

struct worker {
        Manager *manager;
        struct udev_list_node node;
        int refcount;
        pid_t pid;
        struct udev_monitor *monitor;
        enum worker_state state;
        struct event *event;
};

/* passed from worker to main process */
struct worker_message {
};

static void event_free(struct event *event) {
        int r;

        if (!event)
                return;

        udev_list_node_remove(&event->node);
        udev_device_unref(event->dev);
        udev_device_unref(event->dev_kernel);

        sd_event_source_unref(event->timeout_warning);
        sd_event_source_unref(event->timeout);

        if (event->worker)
                event->worker->event = NULL;

        assert(event->manager);

        if (udev_list_node_is_empty(&event->manager->events)) {
                /* only clean up the queue from the process that created it */
                if (event->manager->pid == getpid()) {
                        r = unlink("/run/udev/queue");
                        if (r < 0)
                                log_warning_errno(errno, "could not unlink /run/udev/queue: %m");
                }
        }

        free(event);
}

static void worker_free(struct worker *worker) {
        if (!worker)
                return;

        assert(worker->manager);

        hashmap_remove(worker->manager->workers, UINT_TO_PTR(worker->pid));
        udev_monitor_unref(worker->monitor);
        event_free(worker->event);

        free(worker);
}

static void manager_workers_free(Manager *manager) {
        struct worker *worker;
        Iterator i;

        assert(manager);

        HASHMAP_FOREACH(worker, manager->workers, i)
                worker_free(worker);

        manager->workers = hashmap_free(manager->workers);
}

static int worker_new(struct worker **ret, Manager *manager, struct udev_monitor *worker_monitor, pid_t pid) {
        _cleanup_free_ struct worker *worker = NULL;
        int r;

        assert(ret);
        assert(manager);
        assert(worker_monitor);
        assert(pid > 1);

        worker = new0(struct worker, 1);
        if (!worker)
                return -ENOMEM;

        worker->refcount = 1;
        worker->manager = manager;
        /* close monitor, but keep address around */
        udev_monitor_disconnect(worker_monitor);
        worker->monitor = udev_monitor_ref(worker_monitor);
        worker->pid = pid;

        r = hashmap_ensure_allocated(&manager->workers, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(manager->workers, UINT_TO_PTR(pid), worker);
        if (r < 0)
                return r;

        *ret = worker;
        worker = NULL;

        return 0;
}

static int on_event_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        struct event *event = userdata;

        assert(event);
        assert(event->worker);

        kill_and_sigcont(event->worker->pid, SIGKILL);
        event->worker->state = WORKER_KILLED;

        log_error("seq %llu '%s' killed", udev_device_get_seqnum(event->dev), event->devpath);

        return 1;
}

static int on_event_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        struct event *event = userdata;

        assert(event);

        log_warning("seq %llu '%s' is taking a long time", udev_device_get_seqnum(event->dev), event->devpath);

        return 1;
}

static void worker_attach_event(struct worker *worker, struct event *event) {
        sd_event *e;
        uint64_t usec;
        int r;

        assert(worker);
        assert(worker->manager);
        assert(event);
        assert(!event->worker);
        assert(!worker->event);

        worker->state = WORKER_RUNNING;
        worker->event = event;
        event->state = EVENT_RUNNING;
        event->worker = worker;

        e = worker->manager->event;

        r = sd_event_now(e, clock_boottime_or_monotonic(), &usec);
        if (r < 0)
                return;

        (void) sd_event_add_time(e, &event->timeout_warning, clock_boottime_or_monotonic(),
                                 usec + arg_event_timeout_warn_usec, USEC_PER_SEC, on_event_timeout_warning, event);

        (void) sd_event_add_time(e, &event->timeout, clock_boottime_or_monotonic(),
                                 usec + arg_event_timeout_usec, USEC_PER_SEC, on_event_timeout, event);
}

static void manager_free(Manager *manager) {
        if (!manager)
                return;

        udev_builtin_exit(manager->udev);

        sd_event_source_unref(manager->ctrl_event);
        sd_event_source_unref(manager->uevent_event);
        sd_event_source_unref(manager->inotify_event);

        udev_unref(manager->udev);
        sd_event_unref(manager->event);
        manager_workers_free(manager);
        event_queue_cleanup(manager, EVENT_UNDEF);

        udev_monitor_unref(manager->monitor);
        udev_ctrl_unref(manager->ctrl);
        udev_ctrl_connection_unref(manager->ctrl_conn_blocking);

        udev_list_cleanup(&manager->properties);
        udev_rules_unref(manager->rules);

        safe_close(manager->fd_inotify);
        safe_close_pair(manager->worker_watch);

        free(manager);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

static int worker_send_message(int fd) {
        struct worker_message message = {};

        return loop_write(fd, &message, sizeof(message), false);
}

static void worker_spawn(Manager *manager, struct event *event) {
        struct udev *udev = event->udev;
        _cleanup_udev_monitor_unref_ struct udev_monitor *worker_monitor = NULL;
        pid_t pid;
        int r = 0;

        /* listen for new events */
        worker_monitor = udev_monitor_new_from_netlink(udev, NULL);
        if (worker_monitor == NULL)
                return;
        /* allow the main daemon netlink address to send devices to the worker */
        udev_monitor_allow_unicast_sender(worker_monitor, manager->monitor);
        r = udev_monitor_enable_receiving(worker_monitor);
        if (r < 0)
                log_error_errno(r, "worker: could not enable receiving of device: %m");

        pid = fork();
        switch (pid) {
        case 0: {
                struct udev_device *dev = NULL;
                _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
                int fd_monitor;
                _cleanup_close_ int fd_signal = -1, fd_ep = -1;
                struct epoll_event ep_signal = { .events = EPOLLIN };
                struct epoll_event ep_monitor = { .events = EPOLLIN };
                sigset_t mask;

                /* take initial device from queue */
                dev = event->dev;
                event->dev = NULL;

                unsetenv("NOTIFY_SOCKET");

                manager_workers_free(manager);
                event_queue_cleanup(manager, EVENT_UNDEF);

                manager->monitor = udev_monitor_unref(manager->monitor);
                manager->ctrl_conn_blocking = udev_ctrl_connection_unref(manager->ctrl_conn_blocking);
                manager->ctrl = udev_ctrl_unref(manager->ctrl);
                manager->ctrl_conn_blocking = udev_ctrl_connection_unref(manager->ctrl_conn_blocking);
                manager->worker_watch[READ_END] = safe_close(manager->worker_watch[READ_END]);

                manager->ctrl_event = sd_event_source_unref(manager->ctrl_event);
                manager->uevent_event = sd_event_source_unref(manager->uevent_event);
                manager->inotify_event = sd_event_source_unref(manager->inotify_event);

                manager->event = sd_event_unref(manager->event);

                sigfillset(&mask);
                fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
                if (fd_signal < 0) {
                        r = log_error_errno(errno, "error creating signalfd %m");
                        goto out;
                }
                ep_signal.data.fd = fd_signal;

                fd_monitor = udev_monitor_get_fd(worker_monitor);
                ep_monitor.data.fd = fd_monitor;

                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0) {
                        r = log_error_errno(errno, "error creating epoll fd: %m");
                        goto out;
                }

                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
                    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_monitor, &ep_monitor) < 0) {
                        r = log_error_errno(errno, "fail to add fds to epoll: %m");
                        goto out;
                }

                /* request TERM signal if parent exits */
                prctl(PR_SET_PDEATHSIG, SIGTERM);

                /* reset OOM score, we only protect the main daemon */
                write_string_file("/proc/self/oom_score_adj", "0", 0);

                for (;;) {
                        struct udev_event *udev_event;
                        int fd_lock = -1;

                        assert(dev);

                        log_debug("seq %llu running", udev_device_get_seqnum(dev));
                        udev_event = udev_event_new(dev);
                        if (udev_event == NULL) {
                                r = -ENOMEM;
                                goto out;
                        }

                        if (arg_exec_delay > 0)
                                udev_event->exec_delay = arg_exec_delay;

                        /*
                         * Take a shared lock on the device node; this establishes
                         * a concept of device "ownership" to serialize device
                         * access. External processes holding an exclusive lock will
                         * cause udev to skip the event handling; in the case udev
                         * acquired the lock, the external process can block until
                         * udev has finished its event handling.
                         */
                        if (!streq_ptr(udev_device_get_action(dev), "remove") &&
                            streq_ptr("block", udev_device_get_subsystem(dev)) &&
                            !startswith(udev_device_get_sysname(dev), "dm-") &&
                            !startswith(udev_device_get_sysname(dev), "md")) {
                                struct udev_device *d = dev;

                                if (streq_ptr("partition", udev_device_get_devtype(d)))
                                        d = udev_device_get_parent(d);

                                if (d) {
                                        fd_lock = open(udev_device_get_devnode(d), O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                                        if (fd_lock >= 0 && flock(fd_lock, LOCK_SH|LOCK_NB) < 0) {
                                                log_debug_errno(errno, "Unable to flock(%s), skipping event handling: %m", udev_device_get_devnode(d));
                                                fd_lock = safe_close(fd_lock);
                                                goto skip;
                                        }
                                }
                        }

                        /* needed for renaming netifs */
                        udev_event->rtnl = rtnl;

                        /* apply rules, create node, symlinks */
                        udev_event_execute_rules(udev_event,
                                                 arg_event_timeout_usec, arg_event_timeout_warn_usec,
                                                 &manager->properties,
                                                 manager->rules);

                        udev_event_execute_run(udev_event,
                                               arg_event_timeout_usec, arg_event_timeout_warn_usec);

                        if (udev_event->rtnl)
                                /* in case rtnl was initialized */
                                rtnl = sd_netlink_ref(udev_event->rtnl);

                        /* apply/restore inotify watch */
                        if (udev_event->inotify_watch) {
                                udev_watch_begin(udev, dev);
                                udev_device_update_db(dev);
                        }

                        safe_close(fd_lock);

                        /* send processed event back to libudev listeners */
                        udev_monitor_send_device(worker_monitor, NULL, dev);

skip:
                        log_debug("seq %llu processed", udev_device_get_seqnum(dev));

                        /* send udevd the result of the event execution */
                        r = worker_send_message(manager->worker_watch[WRITE_END]);
                        if (r < 0)
                                log_error_errno(r, "failed to send result of seq %llu to main daemon: %m",
                                                udev_device_get_seqnum(dev));

                        udev_device_unref(dev);
                        dev = NULL;

                        udev_event_unref(udev_event);

                        /* wait for more device messages from main udevd, or term signal */
                        while (dev == NULL) {
                                struct epoll_event ev[4];
                                int fdcount;
                                int i;

                                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                                if (fdcount < 0) {
                                        if (errno == EINTR)
                                                continue;
                                        r = log_error_errno(errno, "failed to poll: %m");
                                        goto out;
                                }

                                for (i = 0; i < fdcount; i++) {
                                        if (ev[i].data.fd == fd_monitor && ev[i].events & EPOLLIN) {
                                                dev = udev_monitor_receive_device(worker_monitor);
                                                break;
                                        } else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN) {
                                                struct signalfd_siginfo fdsi;
                                                ssize_t size;

                                                size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                                                if (size != sizeof(struct signalfd_siginfo))
                                                        continue;
                                                switch (fdsi.ssi_signo) {
                                                case SIGTERM:
                                                        goto out;
                                                }
                                        }
                                }
                        }
                }
out:
                udev_device_unref(dev);
                manager_free(manager);
                log_close();
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }
        case -1:
                event->state = EVENT_QUEUED;
                log_error_errno(errno, "fork of child failed: %m");
                break;
        default:
        {
                struct worker *worker;

                r = worker_new(&worker, manager, worker_monitor, pid);
                if (r < 0)
                        return;

                worker_attach_event(worker, event);

                log_debug("seq %llu forked new worker ["PID_FMT"]", udev_device_get_seqnum(event->dev), pid);
                break;
        }
        }
}

static void event_run(Manager *manager, struct event *event) {
        struct worker *worker;
        Iterator i;

        assert(manager);
        assert(event);

        HASHMAP_FOREACH(worker, manager->workers, i) {
                ssize_t count;

                if (worker->state != WORKER_IDLE)
                        continue;

                count = udev_monitor_send_device(manager->monitor, worker->monitor, event->dev);
                if (count < 0) {
                        log_error_errno(errno, "worker ["PID_FMT"] did not accept message %zi (%m), kill it",
                                        worker->pid, count);
                        kill(worker->pid, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_attach_event(worker, event);
                return;
        }

        if (hashmap_size(manager->workers) >= arg_children_max) {
                if (arg_children_max > 1)
                        log_debug("maximum number (%i) of children reached", hashmap_size(manager->workers));
                return;
        }

        /* start new worker and pass initial device */
        worker_spawn(manager, event);
}

static int event_queue_insert(Manager *manager, struct udev_device *dev) {
        struct event *event;
        int r;

        assert(manager);
        assert(dev);

        /* only one process can add events to the queue */
        if (manager->pid == 0)
                manager->pid = getpid();

        assert(manager->pid == getpid());

        event = new0(struct event, 1);
        if (!event)
                return -ENOMEM;

        event->udev = udev_device_get_udev(dev);
        event->manager = manager;
        event->dev = dev;
        event->dev_kernel = udev_device_shallow_clone(dev);
        udev_device_copy_properties(event->dev_kernel, dev);
        event->seqnum = udev_device_get_seqnum(dev);
        event->devpath = udev_device_get_devpath(dev);
        event->devpath_len = strlen(event->devpath);
        event->devpath_old = udev_device_get_devpath_old(dev);
        event->devnum = udev_device_get_devnum(dev);
        event->is_block = streq("block", udev_device_get_subsystem(dev));
        event->ifindex = udev_device_get_ifindex(dev);

        log_debug("seq %llu queued, '%s' '%s'", udev_device_get_seqnum(dev),
             udev_device_get_action(dev), udev_device_get_subsystem(dev));

        event->state = EVENT_QUEUED;

        if (udev_list_node_is_empty(&manager->events)) {
                r = touch("/run/udev/queue");
                if (r < 0)
                        log_warning_errno(r, "could not touch /run/udev/queue: %m");
        }

        udev_list_node_append(&event->node, &manager->events);

        return 0;
}

static void manager_kill_workers(Manager *manager) {
        struct worker *worker;
        Iterator i;

        assert(manager);

        HASHMAP_FOREACH(worker, manager->workers, i) {
                if (worker->state == WORKER_KILLED)
                        continue;

                worker->state = WORKER_KILLED;
                kill(worker->pid, SIGTERM);
        }
}

/* lookup event for identical, parent, child device */
static bool is_devpath_busy(Manager *manager, struct event *event) {
        struct udev_list_node *loop;
        size_t common;

        /* check if queue contains events we depend on */
        udev_list_node_foreach(loop, &manager->events) {
                struct event *loop_event = node_to_event(loop);

                /* we already found a later event, earlier can not block us, no need to check again */
                if (loop_event->seqnum < event->delaying_seqnum)
                        continue;

                /* event we checked earlier still exists, no need to check again */
                if (loop_event->seqnum == event->delaying_seqnum)
                        return true;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        break;

                /* check major/minor */
                if (major(event->devnum) != 0 && event->devnum == loop_event->devnum && event->is_block == loop_event->is_block)
                        return true;

                /* check network device ifindex */
                if (event->ifindex != 0 && event->ifindex == loop_event->ifindex)
                        return true;

                /* check our old name */
                if (event->devpath_old != NULL && streq(loop_event->devpath, event->devpath_old)) {
                        event->delaying_seqnum = loop_event->seqnum;
                        return true;
                }

                /* compare devpath */
                common = MIN(loop_event->devpath_len, event->devpath_len);

                /* one devpath is contained in the other? */
                if (memcmp(loop_event->devpath, event->devpath, common) != 0)
                        continue;

                /* identical device event found */
                if (loop_event->devpath_len == event->devpath_len) {
                        /* devices names might have changed/swapped in the meantime */
                        if (major(event->devnum) != 0 && (event->devnum != loop_event->devnum || event->is_block != loop_event->is_block))
                                continue;
                        if (event->ifindex != 0 && event->ifindex != loop_event->ifindex)
                                continue;
                        event->delaying_seqnum = loop_event->seqnum;
                        return true;
                }

                /* parent device event found */
                if (event->devpath[common] == '/') {
                        event->delaying_seqnum = loop_event->seqnum;
                        return true;
                }

                /* child device event found */
                if (loop_event->devpath[common] == '/') {
                        event->delaying_seqnum = loop_event->seqnum;
                        return true;
                }

                /* no matching device */
                continue;
        }

        return false;
}

static int on_exit_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = userdata;

        assert(manager);

        log_error_errno(ETIMEDOUT, "giving up waiting for workers to finish");

        sd_event_exit(manager->event, -ETIMEDOUT);

        return 1;
}

static void manager_exit(Manager *manager) {
        uint64_t usec;
        int r;

        assert(manager);

        manager->exit = true;

        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Starting shutdown...");

        /* close sources of new events and discard buffered events */
        manager->ctrl_event = sd_event_source_unref(manager->ctrl_event);
        manager->ctrl = udev_ctrl_unref(manager->ctrl);

        manager->inotify_event = sd_event_source_unref(manager->inotify_event);
        manager->fd_inotify = safe_close(manager->fd_inotify);

        manager->uevent_event = sd_event_source_unref(manager->uevent_event);
        manager->monitor = udev_monitor_unref(manager->monitor);

        /* discard queued events and kill workers */
        event_queue_cleanup(manager, EVENT_QUEUED);
        manager_kill_workers(manager);

        r = sd_event_now(manager->event, clock_boottime_or_monotonic(), &usec);
        if (r < 0)
                return;

        r = sd_event_add_time(manager->event, NULL, clock_boottime_or_monotonic(),
                              usec + 30 * USEC_PER_SEC, USEC_PER_SEC, on_exit_timeout, manager);
        if (r < 0)
                return;
}

/* reload requested, HUP signal received, rules changed, builtin changed */
static void manager_reload(Manager *manager) {

        assert(manager);

        sd_notify(false,
                  "RELOADING=1\n"
                  "STATUS=Flushing configuration...");

        manager_kill_workers(manager);
        manager->rules = udev_rules_unref(manager->rules);
        udev_builtin_exit(manager->udev);

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing...");
}

static void event_queue_start(Manager *manager) {
        struct udev_list_node *loop;
        usec_t usec;
        int r;

        assert(manager);

        if (udev_list_node_is_empty(&manager->events) ||
            manager->exit || manager->stop_exec_queue)
                return;

        r = sd_event_now(manager->event, clock_boottime_or_monotonic(), &usec);
        if (r >= 0) {
                /* check for changed config, every 3 seconds at most */
                if (manager->last_usec == 0 ||
                    (usec - manager->last_usec) > 3 * USEC_PER_SEC) {
                        if (udev_rules_check_timestamp(manager->rules) ||
                            udev_builtin_validate(manager->udev))
                                manager_reload(manager);

                        manager->last_usec = usec;
                }
        }

        udev_builtin_init(manager->udev);

        if (!manager->rules) {
                manager->rules = udev_rules_new(manager->udev, arg_resolve_names);
                if (!manager->rules)
                        return;
        }

        udev_list_node_foreach(loop, &manager->events) {
                struct event *event = node_to_event(loop);

                if (event->state != EVENT_QUEUED)
                        continue;

                /* do not start event if parent or child event is still running */
                if (is_devpath_busy(manager, event))
                        continue;

                event_run(manager, event);
        }
}

static void event_queue_cleanup(Manager *manager, enum event_state match_type) {
        struct udev_list_node *loop, *tmp;

        udev_list_node_foreach_safe(loop, tmp, &manager->events) {
                struct event *event = node_to_event(loop);

                if (match_type != EVENT_UNDEF && match_type != event->state)
                        continue;

                event_free(event);
        }
}

static int on_worker(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = userdata;

        assert(manager);

        for (;;) {
                struct worker_message msg;
                struct iovec iovec = {
                        .iov_base = &msg,
                        .iov_len = sizeof(msg),
                };
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control = {};
                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };
                struct cmsghdr *cmsg;
                ssize_t size;
                struct ucred *ucred = NULL;
                struct worker *worker;

                size = recvmsg(fd, &msghdr, MSG_DONTWAIT);
                if (size < 0) {
                        if (errno == EINTR)
                                continue;
                        else if (errno == EAGAIN)
                                /* nothing more to read */
                                break;

                        return log_error_errno(errno, "failed to receive message: %m");
                } else if (size != sizeof(struct worker_message)) {
                        log_warning_errno(EIO, "ignoring worker message with invalid size %zi bytes", size);
                        continue;
                }

                CMSG_FOREACH(cmsg, &msghdr) {
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_CREDENTIALS &&
                            cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)))
                                ucred = (struct ucred*) CMSG_DATA(cmsg);
                }

                if (!ucred || ucred->pid <= 0) {
                        log_warning_errno(EIO, "ignoring worker message without valid PID");
                        continue;
                }

                /* lookup worker who sent the signal */
                worker = hashmap_get(manager->workers, UINT_TO_PTR(ucred->pid));
                if (!worker) {
                        log_debug("worker ["PID_FMT"] returned, but is no longer tracked", ucred->pid);
                        continue;
                }

                if (worker->state != WORKER_KILLED)
                        worker->state = WORKER_IDLE;

                /* worker returned */
                event_free(worker->event);
        }

        /* we have free workers, try to schedule events */
        event_queue_start(manager);

        return 1;
}

static int on_uevent(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = userdata;
        struct udev_device *dev;
        int r;

        assert(manager);

        dev = udev_monitor_receive_device(manager->monitor);
        if (dev) {
                udev_device_ensure_usec_initialized(dev, NULL);
                r = event_queue_insert(manager, dev);
                if (r < 0)
                        udev_device_unref(dev);
                else
                        /* we have fresh events, try to schedule them */
                        event_queue_start(manager);
        }

        return 1;
}

/* receive the udevd message from userspace */
static int on_ctrl_msg(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = userdata;
        _cleanup_udev_ctrl_connection_unref_ struct udev_ctrl_connection *ctrl_conn = NULL;
        _cleanup_udev_ctrl_msg_unref_ struct udev_ctrl_msg *ctrl_msg = NULL;
        const char *str;
        int i;

        assert(manager);

        ctrl_conn = udev_ctrl_get_connection(manager->ctrl);
        if (!ctrl_conn)
                return 1;

        ctrl_msg = udev_ctrl_receive_msg(ctrl_conn);
        if (!ctrl_msg)
                return 1;

        i = udev_ctrl_get_set_log_level(ctrl_msg);
        if (i >= 0) {
                log_debug("udevd message (SET_LOG_LEVEL) received, log_priority=%i", i);
                log_set_max_level(i);
                manager_kill_workers(manager);
        }

        if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (STOP_EXEC_QUEUE) received");
                manager->stop_exec_queue = true;
        }

        if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (START_EXEC_QUEUE) received");
                manager->stop_exec_queue = false;
                event_queue_start(manager);
        }

        if (udev_ctrl_get_reload(ctrl_msg) > 0) {
                log_debug("udevd message (RELOAD) received");
                manager_reload(manager);
        }

        str = udev_ctrl_get_set_env(ctrl_msg);
        if (str != NULL) {
                _cleanup_free_ char *key = NULL;

                key = strdup(str);
                if (key) {
                        char *val;

                        val = strchr(key, '=');
                        if (val != NULL) {
                                val[0] = '\0';
                                val = &val[1];
                                if (val[0] == '\0') {
                                        log_debug("udevd message (ENV) received, unset '%s'", key);
                                        udev_list_entry_add(&manager->properties, key, NULL);
                                } else {
                                        log_debug("udevd message (ENV) received, set '%s=%s'", key, val);
                                        udev_list_entry_add(&manager->properties, key, val);
                                }
                        } else
                                log_error("wrong key format '%s'", key);
                }
                manager_kill_workers(manager);
        }

        i = udev_ctrl_get_set_children_max(ctrl_msg);
        if (i >= 0) {
                log_debug("udevd message (SET_MAX_CHILDREN) received, children_max=%i", i);
                arg_children_max = i;
        }

        if (udev_ctrl_get_ping(ctrl_msg) > 0)
                log_debug("udevd message (SYNC) received");

        if (udev_ctrl_get_exit(ctrl_msg) > 0) {
                log_debug("udevd message (EXIT) received");
                manager_exit(manager);
                /* keep reference to block the client until we exit
                   TODO: deal with several blocking exit requests */
                manager->ctrl_conn_blocking = udev_ctrl_connection_ref(ctrl_conn);
        }

        return 1;
}

static int synthesize_change(struct udev_device *dev) {
        char filename[UTIL_PATH_SIZE];
        int r;

        if (streq_ptr("block", udev_device_get_subsystem(dev)) &&
            streq_ptr("disk", udev_device_get_devtype(dev)) &&
            !startswith(udev_device_get_sysname(dev), "dm-")) {
                bool part_table_read = false;
                bool has_partitions = false;
                int fd;
                struct udev *udev = udev_device_get_udev(dev);
                _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
                struct udev_list_entry *item;

                /*
                 * Try to re-read the partition table. This only succeeds if
                 * none of the devices is busy. The kernel returns 0 if no
                 * partition table is found, and we will not get an event for
                 * the disk.
                 */
                fd = open(udev_device_get_devnode(dev), O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                if (fd >= 0) {
                        r = flock(fd, LOCK_EX|LOCK_NB);
                        if (r >= 0)
                                r = ioctl(fd, BLKRRPART, 0);

                        close(fd);
                        if (r >= 0)
                                part_table_read = true;
                }

                /* search for partitions */
                e = udev_enumerate_new(udev);
                if (!e)
                        return -ENOMEM;

                r = udev_enumerate_add_match_parent(e, dev);
                if (r < 0)
                        return r;

                r = udev_enumerate_add_match_subsystem(e, "block");
                if (r < 0)
                        return r;

                r = udev_enumerate_scan_devices(e);
                if (r < 0)
                        return r;

                udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                        _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                        d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                        if (!d)
                                continue;

                        if (!streq_ptr("partition", udev_device_get_devtype(d)))
                                continue;

                        has_partitions = true;
                        break;
                }

                /*
                 * We have partitions and re-read the table, the kernel already sent
                 * out a "change" event for the disk, and "remove/add" for all
                 * partitions.
                 */
                if (part_table_read && has_partitions)
                        return 0;

                /*
                 * We have partitions but re-reading the partition table did not
                 * work, synthesize "change" for the disk and all partitions.
                 */
                log_debug("device %s closed, synthesising 'change'", udev_device_get_devnode(dev));
                strscpyl(filename, sizeof(filename), udev_device_get_syspath(dev), "/uevent", NULL);
                write_string_file(filename, "change", WRITE_STRING_FILE_CREATE);

                udev_list_entry_foreach(item, udev_enumerate_get_list_entry(e)) {
                        _cleanup_udev_device_unref_ struct udev_device *d = NULL;

                        d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                        if (!d)
                                continue;

                        if (!streq_ptr("partition", udev_device_get_devtype(d)))
                                continue;

                        log_debug("device %s closed, synthesising partition '%s' 'change'",
                                  udev_device_get_devnode(dev), udev_device_get_devnode(d));
                        strscpyl(filename, sizeof(filename), udev_device_get_syspath(d), "/uevent", NULL);
                        write_string_file(filename, "change", WRITE_STRING_FILE_CREATE);
                }

                return 0;
        }

        log_debug("device %s closed, synthesising 'change'", udev_device_get_devnode(dev));
        strscpyl(filename, sizeof(filename), udev_device_get_syspath(dev), "/uevent", NULL);
        write_string_file(filename, "change", WRITE_STRING_FILE_CREATE);

        return 0;
}

static int on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = userdata;
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;

        assert(manager);

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 1;

                return log_error_errno(errno, "Failed to read inotify fd: %m");
        }

        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                _cleanup_udev_device_unref_ struct udev_device *dev = NULL;

                dev = udev_watch_lookup(manager->udev, e->wd);
                if (!dev)
                        continue;

                log_debug("inotify event: %x for %s", e->mask, udev_device_get_devnode(dev));
                if (e->mask & IN_CLOSE_WRITE) {
                        synthesize_change(dev);

                        /* settle might be waiting on us to determine the queue
                         * state. If we just handled an inotify event, we might have
                         * generated a "change" event, but we won't have queued up
                         * the resultant uevent yet. Do that.
                         */
                        on_uevent(NULL, -1, 0, manager);
                } else if (e->mask & IN_IGNORED)
                        udev_watch_end(manager->udev, dev);
        }

        return 1;
}

static int on_sigterm(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = userdata;

        assert(manager);

        manager_exit(manager);

        return 1;
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = userdata;

        assert(manager);

        manager_reload(manager);

        return 1;
}

static int on_sigchld(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = userdata;

        assert(manager);

        for (;;) {
                pid_t pid;
                int status;
                struct worker *worker;

                pid = waitpid(-1, &status, WNOHANG);
                if (pid <= 0)
                        break;

                worker = hashmap_get(manager->workers, UINT_TO_PTR(pid));
                if (!worker) {
                        log_warning("worker ["PID_FMT"] is unknown, ignoring", pid);
                        continue;
                }

                if (WIFEXITED(status)) {
                        if (WEXITSTATUS(status) == 0)
                                log_debug("worker ["PID_FMT"] exited", pid);
                        else
                                log_warning("worker ["PID_FMT"] exited with return code %i", pid, WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                        log_warning("worker ["PID_FMT"] terminated by signal %i (%s)", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                } else if (WIFSTOPPED(status)) {
                        log_info("worker ["PID_FMT"] stopped", pid);
                        continue;
                } else if (WIFCONTINUED(status)) {
                        log_info("worker ["PID_FMT"] continued", pid);
                        continue;
                } else
                        log_warning("worker ["PID_FMT"] exit with status 0x%04x", pid, status);

                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                        if (worker->event) {
                                log_error("worker ["PID_FMT"] failed while handling '%s'", pid, worker->event->devpath);
                                /* delete state from disk */
                                udev_device_delete_db(worker->event->dev);
                                udev_device_tag_index(worker->event->dev, NULL, false);
                                /* forward kernel event without amending it */
                                udev_monitor_send_device(manager->monitor, NULL, worker->event->dev_kernel);
                        }
                }

                worker_free(worker);
        }

        /* we can start new workers, try to schedule events */
        event_queue_start(manager);

        return 1;
}

static int on_post(sd_event_source *s, void *userdata) {
        Manager *manager = userdata;
        int r;

        assert(manager);

        if (udev_list_node_is_empty(&manager->events)) {
                /* no pending events */
                if (!hashmap_isempty(manager->workers)) {
                        /* there are idle workers */
                        log_debug("cleanup idle workers");
                        manager_kill_workers(manager);
                } else {
                        /* we are idle */
                        if (manager->exit) {
                                r = sd_event_exit(manager->event, 0);
                                if (r < 0)
                                        return r;
                        } else if (manager->cgroup)
                                /* cleanup possible left-over processes in our cgroup */
                                cg_kill(SYSTEMD_CGROUP_CONTROLLER, manager->cgroup, SIGKILL, false, true, NULL);
                }
        }

        return 1;
}

static int listen_fds(int *rctrl, int *rnetlink) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        int ctrl_fd = -1, netlink_fd = -1;
        int fd, n, r;

        assert(rctrl);
        assert(rnetlink);

        n = sd_listen_fds(true);
        if (n < 0)
                return n;

        for (fd = SD_LISTEN_FDS_START; fd < n + SD_LISTEN_FDS_START; fd++) {
                if (sd_is_socket(fd, AF_LOCAL, SOCK_SEQPACKET, -1)) {
                        if (ctrl_fd >= 0)
                                return -EINVAL;
                        ctrl_fd = fd;
                        continue;
                }

                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1)) {
                        if (netlink_fd >= 0)
                                return -EINVAL;
                        netlink_fd = fd;
                        continue;
                }

                return -EINVAL;
        }

        if (ctrl_fd < 0) {
                _cleanup_udev_ctrl_unref_ struct udev_ctrl *ctrl = NULL;

                udev = udev_new();
                if (!udev)
                        return -ENOMEM;

                ctrl = udev_ctrl_new(udev);
                if (!ctrl)
                        return log_error_errno(EINVAL, "error initializing udev control socket");

                r = udev_ctrl_enable_receiving(ctrl);
                if (r < 0)
                        return log_error_errno(EINVAL, "error binding udev control socket");

                fd = udev_ctrl_get_fd(ctrl);
                if (fd < 0)
                        return log_error_errno(EIO, "could not get ctrl fd");

                ctrl_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (ctrl_fd < 0)
                        return log_error_errno(errno, "could not dup ctrl fd: %m");
        }

        if (netlink_fd < 0) {
                _cleanup_udev_monitor_unref_ struct udev_monitor *monitor = NULL;

                if (!udev) {
                        udev = udev_new();
                        if (!udev)
                                return -ENOMEM;
                }

                monitor = udev_monitor_new_from_netlink(udev, "kernel");
                if (!monitor)
                        return log_error_errno(EINVAL, "error initializing netlink socket");

                (void) udev_monitor_set_receive_buffer_size(monitor, 128 * 1024 * 1024);

                r = udev_monitor_enable_receiving(monitor);
                if (r < 0)
                        return log_error_errno(EINVAL, "error binding netlink socket");

                fd = udev_monitor_get_fd(monitor);
                if (fd < 0)
                        return log_error_errno(netlink_fd, "could not get uevent fd: %m");

                netlink_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (ctrl_fd < 0)
                        return log_error_errno(errno, "could not dup netlink fd: %m");
        }

        *rctrl = ctrl_fd;
        *rnetlink = netlink_fd;

        return 0;
}

/*
 * read the kernel command line, in case we need to get into debug mode
 *   udev.log-priority=<level>                 syslog priority
 *   udev.children-max=<number of workers>     events are fully serialized if set to 1
 *   udev.exec-delay=<number of seconds>       delay execution of every executed program
 *   udev.event-timeout=<number of seconds>    seconds to wait before terminating an event
 */
static int parse_proc_cmdline_item(const char *key, const char *value) {
        const char *full_key = key;
        int r;

        assert(key);

        if (!value)
                return 0;

        if (startswith(key, "rd."))
                key += strlen("rd.");

        if (startswith(key, "udev."))
                key += strlen("udev.");
        else
                return 0;

        if (streq(key, "log-priority")) {
                int prio;

                prio = util_log_priority(value);
                if (prio < 0)
                        goto invalid;
                log_set_max_level(prio);
        } else if (streq(key, "children-max")) {
                r = safe_atou(value, &arg_children_max);
                if (r < 0)
                        goto invalid;
        } else if (streq(key, "exec-delay")) {
                r = safe_atoi(value, &arg_exec_delay);
                if (r < 0)
                        goto invalid;
        } else if (streq(key, "event-timeout")) {
                r = safe_atou64(value, &arg_event_timeout_usec);
                if (r < 0)
                        goto invalid;
                arg_event_timeout_usec *= USEC_PER_SEC;
                arg_event_timeout_warn_usec = (arg_event_timeout_usec / 3) ? : 1;
        }

        return 0;
invalid:
        log_warning("invalid %s ignored: %s", full_key, value);
        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Manages devices.\n\n"
               "  -h --help                   Print this message\n"
               "     --version                Print version of the program\n"
               "     --daemon                 Detach and run in the background\n"
               "     --debug                  Enable debug output\n"
               "     --children-max=INT       Set maximum number of workers\n"
               "     --exec-delay=SECONDS     Seconds to wait before executing RUN=\n"
               "     --event-timeout=SECONDS  Seconds to wait before terminating an event\n"
               "     --resolve-names=early|late|never\n"
               "                              When to resolve users and groups\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "daemon",             no_argument,            NULL, 'd' },
                { "debug",              no_argument,            NULL, 'D' },
                { "children-max",       required_argument,      NULL, 'c' },
                { "exec-delay",         required_argument,      NULL, 'e' },
                { "event-timeout",      required_argument,      NULL, 't' },
                { "resolve-names",      required_argument,      NULL, 'N' },
                { "help",               no_argument,            NULL, 'h' },
                { "version",            no_argument,            NULL, 'V' },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "c:de:Dt:N:hV", options, NULL)) >= 0) {
                int r;

                switch (c) {

                case 'd':
                        arg_daemonize = true;
                        break;
                case 'c':
                        r = safe_atou(optarg, &arg_children_max);
                        if (r < 0)
                                log_warning("Invalid --children-max ignored: %s", optarg);
                        break;
                case 'e':
                        r = safe_atoi(optarg, &arg_exec_delay);
                        if (r < 0)
                                log_warning("Invalid --exec-delay ignored: %s", optarg);
                        break;
                case 't':
                        r = safe_atou64(optarg, &arg_event_timeout_usec);
                        if (r < 0)
                                log_warning("Invalid --event-timeout ignored: %s", optarg);
                        else {
                                arg_event_timeout_usec *= USEC_PER_SEC;
                                arg_event_timeout_warn_usec = (arg_event_timeout_usec / 3) ? : 1;
                        }
                        break;
                case 'D':
                        arg_debug = true;
                        break;
                case 'N':
                        if (streq(optarg, "early")) {
                                arg_resolve_names = 1;
                        } else if (streq(optarg, "late")) {
                                arg_resolve_names = 0;
                        } else if (streq(optarg, "never")) {
                                arg_resolve_names = -1;
                        } else {
                                log_error("resolve-names must be early, late or never");
                                return 0;
                        }
                        break;
                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", VERSION);
                        return 0;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unhandled option");

                }
        }

        return 1;
}

static int manager_new(Manager **ret, int fd_ctrl, int fd_uevent, const char *cgroup) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        int r, fd_worker, one = 1;

        assert(ret);
        assert(fd_ctrl >= 0);
        assert(fd_uevent >= 0);

        manager = new0(Manager, 1);
        if (!manager)
                return log_oom();

        manager->fd_inotify = -1;
        manager->worker_watch[WRITE_END] = -1;
        manager->worker_watch[READ_END] = -1;

        manager->udev = udev_new();
        if (!manager->udev)
                return log_error_errno(errno, "could not allocate udev context: %m");

        udev_builtin_init(manager->udev);

        manager->rules = udev_rules_new(manager->udev, arg_resolve_names);
        if (!manager->rules)
                return log_error_errno(ENOMEM, "error reading rules");

        udev_list_node_init(&manager->events);
        udev_list_init(manager->udev, &manager->properties, true);

        manager->cgroup = cgroup;

        manager->ctrl = udev_ctrl_new_from_fd(manager->udev, fd_ctrl);
        if (!manager->ctrl)
                return log_error_errno(EINVAL, "error taking over udev control socket");

        manager->monitor = udev_monitor_new_from_netlink_fd(manager->udev, "kernel", fd_uevent);
        if (!manager->monitor)
                return log_error_errno(EINVAL, "error taking over netlink socket");

        /* unnamed socket from workers to the main daemon */
        r = socketpair(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0, manager->worker_watch);
        if (r < 0)
                return log_error_errno(errno, "error creating socketpair: %m");

        fd_worker = manager->worker_watch[READ_END];

        r = setsockopt(fd_worker, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "could not enable SO_PASSCRED: %m");

        manager->fd_inotify = udev_watch_init(manager->udev);
        if (manager->fd_inotify < 0)
                return log_error_errno(ENOMEM, "error initializing inotify");

        udev_watch_restore(manager->udev);

        /* block and listen to all signals on signalfd */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, -1) >= 0);

        r = sd_event_default(&manager->event);
        if (r < 0)
                return log_error_errno(errno, "could not allocate event loop: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGINT, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "error creating sigint event source: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGTERM, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "error creating sigterm event source: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGHUP, on_sighup, manager);
        if (r < 0)
                return log_error_errno(r, "error creating sighup event source: %m");

        r = sd_event_add_signal(manager->event, NULL, SIGCHLD, on_sigchld, manager);
        if (r < 0)
                return log_error_errno(r, "error creating sigchld event source: %m");

        r = sd_event_set_watchdog(manager->event, true);
        if (r < 0)
                return log_error_errno(r, "error creating watchdog event source: %m");

        r = sd_event_add_io(manager->event, &manager->ctrl_event, fd_ctrl, EPOLLIN, on_ctrl_msg, manager);
        if (r < 0)
                return log_error_errno(r, "error creating ctrl event source: %m");

        /* This needs to be after the inotify and uevent handling, to make sure
         * that the ping is send back after fully processing the pending uevents
         * (including the synthetic ones we may create due to inotify events).
         */
        r = sd_event_source_set_priority(manager->ctrl_event, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "cold not set IDLE event priority for ctrl event source: %m");

        r = sd_event_add_io(manager->event, &manager->inotify_event, manager->fd_inotify, EPOLLIN, on_inotify, manager);
        if (r < 0)
                return log_error_errno(r, "error creating inotify event source: %m");

        r = sd_event_add_io(manager->event, &manager->uevent_event, fd_uevent, EPOLLIN, on_uevent, manager);
        if (r < 0)
                return log_error_errno(r, "error creating uevent event source: %m");

        r = sd_event_add_io(manager->event, NULL, fd_worker, EPOLLIN, on_worker, manager);
        if (r < 0)
                return log_error_errno(r, "error creating worker event source: %m");

        r = sd_event_add_post(manager->event, NULL, on_post, manager);
        if (r < 0)
                return log_error_errno(r, "error creating post event source: %m");

        *ret = manager;
        manager = NULL;

        return 0;
}

static int run(int fd_ctrl, int fd_uevent, const char *cgroup) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        r = manager_new(&manager, fd_ctrl, fd_uevent, cgroup);
        if (r < 0) {
                r = log_error_errno(r, "failed to allocate manager object: %m");
                goto exit;
        }

        r = udev_rules_apply_static_dev_perms(manager->rules);
        if (r < 0)
                log_error_errno(r, "failed to apply permissions on static device nodes: %m");

        (void) sd_notify(false,
                         "READY=1\n"
                         "STATUS=Processing...");

        r = sd_event_loop(manager->event);
        if (r < 0) {
                log_error_errno(r, "event loop failed: %m");
                goto exit;
        }

        sd_event_get_exit_code(manager->event, &r);

exit:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");
        if (manager)
                udev_ctrl_cleanup(manager->ctrl);
        return r;
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *cgroup = NULL;
        int r, fd_ctrl, fd_uevent;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto exit;

        r = parse_proc_cmdline(parse_proc_cmdline_item);
        if (r < 0)
                log_warning_errno(r, "failed to parse kernel command line, ignoring: %m");

        if (arg_debug) {
                log_set_target(LOG_TARGET_CONSOLE);
                log_set_max_level(LOG_DEBUG);
        }

        if (getuid() != 0) {
                r = log_error_errno(EPERM, "root privileges required");
                goto exit;
        }

        if (arg_children_max == 0) {
                cpu_set_t cpu_set;

                arg_children_max = 8;

                if (sched_getaffinity(0, sizeof (cpu_set), &cpu_set) == 0) {
                        arg_children_max += CPU_COUNT(&cpu_set) * 2;
                }

                log_debug("set children_max to %u", arg_children_max);
        }

        /* set umask before creating any file/directory */
        r = chdir("/");
        if (r < 0) {
                r = log_error_errno(errno, "could not change dir to /: %m");
                goto exit;
        }

        umask(022);

        r = mac_selinux_init("/dev");
        if (r < 0) {
                log_error_errno(r, "could not initialize labelling: %m");
                goto exit;
        }

        r = mkdir("/run/udev", 0755);
        if (r < 0 && errno != EEXIST) {
                r = log_error_errno(errno, "could not create /run/udev: %m");
                goto exit;
        }

        dev_setup(NULL, UID_INVALID, GID_INVALID);

        if (getppid() == 1) {
                /* get our own cgroup, we regularly kill everything udev has left behind
                   we only do this on systemd systems, and only if we are directly spawned
                   by PID1. otherwise we are not guaranteed to have a dedicated cgroup */
                r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
                if (r < 0) {
                        if (r == -ENOENT)
                                log_debug_errno(r, "did not find dedicated cgroup: %m");
                        else
                                log_warning_errno(r, "failed to get cgroup: %m");
                }
        }

        r = listen_fds(&fd_ctrl, &fd_uevent);
        if (r < 0) {
                r = log_error_errno(r, "could not listen on fds: %m");
                goto exit;
        }

        if (arg_daemonize) {
                pid_t pid;

                log_info("starting version " VERSION);

                /* connect /dev/null to stdin, stdout, stderr */
                if (log_get_max_level() < LOG_DEBUG)
                        (void) make_null_stdio();

                pid = fork();
                switch (pid) {
                case 0:
                        break;
                case -1:
                        r = log_error_errno(errno, "fork of daemon failed: %m");
                        goto exit;
                default:
                        mac_selinux_finish();
                        log_close();
                        _exit(EXIT_SUCCESS);
                }

                setsid();

                write_string_file("/proc/self/oom_score_adj", "-1000", 0);
        }

        r = run(fd_ctrl, fd_uevent, cgroup);

exit:
        mac_selinux_finish();
        log_close();
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
