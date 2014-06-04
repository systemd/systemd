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
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/utsname.h>

#include "udev.h"
#include "udev-util.h"
#include "sd-daemon.h"
#include "cgroup-util.h"
#include "dev-setup.h"
#include "fileio.h"

static bool debug;

void udev_main_log(struct udev *udev, int priority,
                   const char *file, int line, const char *fn,
                   const char *format, va_list args)
{
        log_metav(priority, file, line, fn, format, args);
}

static struct udev_rules *rules;
static struct udev_ctrl *udev_ctrl;
static struct udev_monitor *monitor;
static int worker_watch[2] = { -1, -1 };
static int fd_signal = -1;
static int fd_ep = -1;
static int fd_inotify = -1;
static bool stop_exec_queue;
static bool reload;
static int children;
static int children_max;
static int exec_delay;
static sigset_t sigmask_orig;
static UDEV_LIST(event_list);
static UDEV_LIST(worker_list);
static char *udev_cgroup;
static bool udev_exit;

enum event_state {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
};

struct event {
        struct udev_list_node node;
        struct udev *udev;
        struct udev_device *dev;
        enum event_state state;
        int exitcode;
        unsigned long long int delaying_seqnum;
        unsigned long long int seqnum;
        const char *devpath;
        size_t devpath_len;
        const char *devpath_old;
        dev_t devnum;
        int ifindex;
        bool is_block;
#ifdef HAVE_FIRMWARE
        bool nodelay;
#endif
};

static inline struct event *node_to_event(struct udev_list_node *node)
{
        return container_of(node, struct event, node);
}

static void event_queue_cleanup(struct udev *udev, enum event_state type);

enum worker_state {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
};

struct worker {
        struct udev_list_node node;
        struct udev *udev;
        int refcount;
        pid_t pid;
        struct udev_monitor *monitor;
        enum worker_state state;
        struct event *event;
        usec_t event_start_usec;
};

/* passed from worker to main process */
struct worker_message {
        pid_t pid;
        int exitcode;
};

static inline struct worker *node_to_worker(struct udev_list_node *node)
{
        return container_of(node, struct worker, node);
}

static void event_queue_delete(struct event *event)
{
        udev_list_node_remove(&event->node);
        udev_device_unref(event->dev);
        free(event);
}

static struct worker *worker_ref(struct worker *worker)
{
        worker->refcount++;
        return worker;
}

static void worker_cleanup(struct worker *worker)
{
        udev_list_node_remove(&worker->node);
        udev_monitor_unref(worker->monitor);
        children--;
        free(worker);
}

static void worker_unref(struct worker *worker)
{
        worker->refcount--;
        if (worker->refcount > 0)
                return;
        log_debug("worker [%u] cleaned up", worker->pid);
        worker_cleanup(worker);
}

static void worker_list_cleanup(struct udev *udev)
{
        struct udev_list_node *loop, *tmp;

        udev_list_node_foreach_safe(loop, tmp, &worker_list) {
                struct worker *worker = node_to_worker(loop);

                worker_cleanup(worker);
        }
}

static void worker_new(struct event *event)
{
        struct udev *udev = event->udev;
        struct worker *worker;
        struct udev_monitor *worker_monitor;
        pid_t pid;

        /* listen for new events */
        worker_monitor = udev_monitor_new_from_netlink(udev, NULL);
        if (worker_monitor == NULL)
                return;
        /* allow the main daemon netlink address to send devices to the worker */
        udev_monitor_allow_unicast_sender(worker_monitor, monitor);
        udev_monitor_enable_receiving(worker_monitor);

        worker = new0(struct worker, 1);
        if (worker == NULL) {
                udev_monitor_unref(worker_monitor);
                return;
        }
        /* worker + event reference */
        worker->refcount = 2;
        worker->udev = udev;

        pid = fork();
        switch (pid) {
        case 0: {
                struct udev_device *dev = NULL;
                int fd_monitor;
                struct epoll_event ep_signal, ep_monitor;
                sigset_t mask;
                int rc = EXIT_SUCCESS;

                /* take initial device from queue */
                dev = event->dev;
                event->dev = NULL;

                free(worker);
                worker_list_cleanup(udev);
                event_queue_cleanup(udev, EVENT_UNDEF);
                udev_monitor_unref(monitor);
                udev_ctrl_unref(udev_ctrl);
                close(fd_signal);
                close(fd_ep);
                close(worker_watch[READ_END]);

                sigfillset(&mask);
                fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
                if (fd_signal < 0) {
                        log_error("error creating signalfd %m");
                        rc = 2;
                        goto out;
                }

                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0) {
                        log_error("error creating epoll fd: %m");
                        rc = 3;
                        goto out;
                }

                memzero(&ep_signal, sizeof(struct epoll_event));
                ep_signal.events = EPOLLIN;
                ep_signal.data.fd = fd_signal;

                fd_monitor = udev_monitor_get_fd(worker_monitor);
                memzero(&ep_monitor, sizeof(struct epoll_event));
                ep_monitor.events = EPOLLIN;
                ep_monitor.data.fd = fd_monitor;

                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
                    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_monitor, &ep_monitor) < 0) {
                        log_error("fail to add fds to epoll: %m");
                        rc = 4;
                        goto out;
                }

                /* request TERM signal if parent exits */
                prctl(PR_SET_PDEATHSIG, SIGTERM);

                /* reset OOM score, we only protect the main daemon */
                write_string_file("/proc/self/oom_score_adj", "0");

                for (;;) {
                        struct udev_event *udev_event;
                        struct worker_message msg;
                        int fd_lock = -1;
                        int err = 0;

                        log_debug("seq %llu running", udev_device_get_seqnum(dev));
                        udev_event = udev_event_new(dev);
                        if (udev_event == NULL) {
                                rc = 5;
                                goto out;
                        }

                        /* needed for SIGCHLD/SIGTERM in spawn() */
                        udev_event->fd_signal = fd_signal;

                        if (exec_delay > 0)
                                udev_event->exec_delay = exec_delay;

                        /*
                         * Take a "read lock" on the device node; this establishes
                         * a concept of device "ownership" to serialize device
                         * access. External processes holding a "write lock" will
                         * cause udev to skip the event handling; in the case udev
                         * acquired the lock, the external process will block until
                         * udev has finished its event handling.
                         */

                        /*
                         * <kabi_> since we make check - device seems unused - we try
                         *         ioctl to deactivate - and device is found to be opened
                         * <kay> sure, you try to take a write lock
                         * <kay> if you get it udev is out
                         * <kay> if you can't get it, udev is busy
                         * <kabi_> we cannot deactivate openned device  (as it is in-use)
                         * <kay> maybe we should just exclude dm from that thing entirely
                         * <kabi_> IMHO this sounds like a good plan for this moment
                         */
                        if (streq_ptr("block", udev_device_get_subsystem(dev)) &&
                            !startswith(udev_device_get_sysname(dev), "dm-")) {
                                struct udev_device *d = dev;

                                if (streq_ptr("partition", udev_device_get_devtype(d)))
                                        d = udev_device_get_parent(d);

                                if (d) {
                                        fd_lock = open(udev_device_get_devnode(d), O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                                        if (fd_lock >= 0 && flock(fd_lock, LOCK_SH|LOCK_NB) < 0) {
                                                log_debug("Unable to flock(%s), skipping event handling: %m", udev_device_get_devnode(d));
                                                err = -EWOULDBLOCK;
                                                fd_lock = safe_close(fd_lock);
                                                goto skip;
                                        }
                                }
                        }

                        /* apply rules, create node, symlinks */
                        udev_event_execute_rules(udev_event, rules, &sigmask_orig);

                        udev_event_execute_run(udev_event, &sigmask_orig);

                        /* apply/restore inotify watch */
                        if (udev_event->inotify_watch) {
                                udev_watch_begin(udev, dev);
                                udev_device_update_db(dev);
                        }

                        safe_close(fd_lock);

                        /* send processed event back to libudev listeners */
                        udev_monitor_send_device(worker_monitor, NULL, dev);

skip:
                        /* send udevd the result of the event execution */
                        memzero(&msg, sizeof(struct worker_message));
                        msg.exitcode = err;
                        msg.pid = getpid();
                        send(worker_watch[WRITE_END], &msg, sizeof(struct worker_message), 0);

                        log_debug("seq %llu processed with %i", udev_device_get_seqnum(dev), err);

                        udev_device_unref(dev);
                        dev = NULL;

                        if (udev_event->sigterm) {
                                udev_event_unref(udev_event);
                                goto out;
                        }

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
                                        log_error("failed to poll: %m");
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
                safe_close(fd_signal);
                safe_close(fd_ep);
                close(fd_inotify);
                close(worker_watch[WRITE_END]);
                udev_rules_unref(rules);
                udev_builtin_exit(udev);
                udev_monitor_unref(worker_monitor);
                udev_unref(udev);
                log_close();
                exit(rc);
        }
        case -1:
                udev_monitor_unref(worker_monitor);
                event->state = EVENT_QUEUED;
                free(worker);
                log_error("fork of child failed: %m");
                break;
        default:
                /* close monitor, but keep address around */
                udev_monitor_disconnect(worker_monitor);
                worker->monitor = worker_monitor;
                worker->pid = pid;
                worker->state = WORKER_RUNNING;
                worker->event_start_usec = now(CLOCK_MONOTONIC);
                worker->event = event;
                event->state = EVENT_RUNNING;
                udev_list_node_append(&worker->node, &worker_list);
                children++;
                log_debug("seq %llu forked new worker [%u]", udev_device_get_seqnum(event->dev), pid);
                break;
        }
}

static void event_run(struct event *event)
{
        struct udev_list_node *loop;

        udev_list_node_foreach(loop, &worker_list) {
                struct worker *worker = node_to_worker(loop);
                ssize_t count;

                if (worker->state != WORKER_IDLE)
                        continue;

                count = udev_monitor_send_device(monitor, worker->monitor, event->dev);
                if (count < 0) {
                        log_error("worker [%u] did not accept message %zi (%m), kill it", worker->pid, count);
                        kill(worker->pid, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_ref(worker);
                worker->event = event;
                worker->state = WORKER_RUNNING;
                worker->event_start_usec = now(CLOCK_MONOTONIC);
                event->state = EVENT_RUNNING;
                return;
        }

        if (children >= children_max) {
                if (children_max > 1)
                        log_debug("maximum number (%i) of children reached", children);
                return;
        }

        /* start new worker and pass initial device */
        worker_new(event);
}

static int event_queue_insert(struct udev_device *dev)
{
        struct event *event;

        event = new0(struct event, 1);
        if (event == NULL)
                return -1;

        event->udev = udev_device_get_udev(dev);
        event->dev = dev;
        event->seqnum = udev_device_get_seqnum(dev);
        event->devpath = udev_device_get_devpath(dev);
        event->devpath_len = strlen(event->devpath);
        event->devpath_old = udev_device_get_devpath_old(dev);
        event->devnum = udev_device_get_devnum(dev);
        event->is_block = streq("block", udev_device_get_subsystem(dev));
        event->ifindex = udev_device_get_ifindex(dev);
#ifdef HAVE_FIRMWARE
        if (streq(udev_device_get_subsystem(dev), "firmware"))
                event->nodelay = true;
#endif

        log_debug("seq %llu queued, '%s' '%s'", udev_device_get_seqnum(dev),
             udev_device_get_action(dev), udev_device_get_subsystem(dev));

        event->state = EVENT_QUEUED;
        udev_list_node_append(&event->node, &event_list);
        return 0;
}

static void worker_kill(struct udev *udev)
{
        struct udev_list_node *loop;

        udev_list_node_foreach(loop, &worker_list) {
                struct worker *worker = node_to_worker(loop);

                if (worker->state == WORKER_KILLED)
                        continue;

                worker->state = WORKER_KILLED;
                kill(worker->pid, SIGTERM);
        }
}

/* lookup event for identical, parent, child device */
static bool is_devpath_busy(struct event *event)
{
        struct udev_list_node *loop;
        size_t common;

        /* check if queue contains events we depend on */
        udev_list_node_foreach(loop, &event_list) {
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

#ifdef HAVE_FIRMWARE
                /* allow to bypass the dependency tracking */
                if (event->nodelay)
                        continue;
#endif

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

static void event_queue_start(struct udev *udev)
{
        struct udev_list_node *loop;

        udev_list_node_foreach(loop, &event_list) {
                struct event *event = node_to_event(loop);

                if (event->state != EVENT_QUEUED)
                        continue;

                /* do not start event if parent or child event is still running */
                if (is_devpath_busy(event))
                        continue;

                event_run(event);
        }
}

static void event_queue_cleanup(struct udev *udev, enum event_state match_type)
{
        struct udev_list_node *loop, *tmp;

        udev_list_node_foreach_safe(loop, tmp, &event_list) {
                struct event *event = node_to_event(loop);

                if (match_type != EVENT_UNDEF && match_type != event->state)
                        continue;

                event_queue_delete(event);
        }
}

static void worker_returned(int fd_worker)
{
        for (;;) {
                struct worker_message msg;
                ssize_t size;
                struct udev_list_node *loop;

                size = recv(fd_worker, &msg, sizeof(struct worker_message), MSG_DONTWAIT);
                if (size != sizeof(struct worker_message))
                        break;

                /* lookup worker who sent the signal */
                udev_list_node_foreach(loop, &worker_list) {
                        struct worker *worker = node_to_worker(loop);

                        if (worker->pid != msg.pid)
                                continue;

                        /* worker returned */
                        if (worker->event) {
                                worker->event->exitcode = msg.exitcode;
                                event_queue_delete(worker->event);
                                worker->event = NULL;
                        }
                        if (worker->state != WORKER_KILLED)
                                worker->state = WORKER_IDLE;
                        worker_unref(worker);
                        break;
                }
        }
}

/* receive the udevd message from userspace */
static struct udev_ctrl_connection *handle_ctrl_msg(struct udev_ctrl *uctrl)
{
        struct udev *udev = udev_ctrl_get_udev(uctrl);
        struct udev_ctrl_connection *ctrl_conn;
        struct udev_ctrl_msg *ctrl_msg = NULL;
        const char *str;
        int i;

        ctrl_conn = udev_ctrl_get_connection(uctrl);
        if (ctrl_conn == NULL)
                goto out;

        ctrl_msg = udev_ctrl_receive_msg(ctrl_conn);
        if (ctrl_msg == NULL)
                goto out;

        i = udev_ctrl_get_set_log_level(ctrl_msg);
        if (i >= 0) {
                log_debug("udevd message (SET_LOG_LEVEL) received, log_priority=%i", i);
                log_set_max_level(i);
                udev_set_log_priority(udev, i);
                worker_kill(udev);
        }

        if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (STOP_EXEC_QUEUE) received");
                stop_exec_queue = true;
        }

        if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
                log_debug("udevd message (START_EXEC_QUEUE) received");
                stop_exec_queue = false;
        }

        if (udev_ctrl_get_reload(ctrl_msg) > 0) {
                log_debug("udevd message (RELOAD) received");
                reload = true;
        }

        str = udev_ctrl_get_set_env(ctrl_msg);
        if (str != NULL) {
                char *key;

                key = strdup(str);
                if (key != NULL) {
                        char *val;

                        val = strchr(key, '=');
                        if (val != NULL) {
                                val[0] = '\0';
                                val = &val[1];
                                if (val[0] == '\0') {
                                        log_debug("udevd message (ENV) received, unset '%s'", key);
                                        udev_add_property(udev, key, NULL);
                                } else {
                                        log_debug("udevd message (ENV) received, set '%s=%s'", key, val);
                                        udev_add_property(udev, key, val);
                                }
                        } else {
                                log_error("wrong key format '%s'", key);
                        }
                        free(key);
                }
                worker_kill(udev);
        }

        i = udev_ctrl_get_set_children_max(ctrl_msg);
        if (i >= 0) {
                log_debug("udevd message (SET_MAX_CHILDREN) received, children_max=%i", i);
                children_max = i;
        }

        if (udev_ctrl_get_ping(ctrl_msg) > 0)
                log_debug("udevd message (SYNC) received");

        if (udev_ctrl_get_exit(ctrl_msg) > 0) {
                log_debug("udevd message (EXIT) received");
                udev_exit = true;
                /* keep reference to block the client until we exit */
                udev_ctrl_connection_ref(ctrl_conn);
        }
out:
        udev_ctrl_msg_unref(ctrl_msg);
        return udev_ctrl_connection_unref(ctrl_conn);
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
                write_string_file(filename, "change");

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
                        write_string_file(filename, "change");
                }

                return 0;
        }

        log_debug("device %s closed, synthesising 'change'", udev_device_get_devnode(dev));
        strscpyl(filename, sizeof(filename), udev_device_get_syspath(dev), "/uevent", NULL);
        write_string_file(filename, "change");

        return 0;
}

static int handle_inotify(struct udev *udev)
{
        int nbytes, pos;
        char *buf;
        struct inotify_event *ev;
        int r;

        r = ioctl(fd_inotify, FIONREAD, &nbytes);
        if (r < 0 || nbytes <= 0)
                return -errno;

        buf = malloc(nbytes);
        if (!buf) {
                log_error("error getting buffer for inotify");
                return -ENOMEM;
        }

        nbytes = read(fd_inotify, buf, nbytes);

        for (pos = 0; pos < nbytes; pos += sizeof(struct inotify_event) + ev->len) {
                struct udev_device *dev;

                ev = (struct inotify_event *)(buf + pos);
                dev = udev_watch_lookup(udev, ev->wd);
                if (!dev)
                        continue;

                log_debug("inotify event: %x for %s", ev->mask, udev_device_get_devnode(dev));
                if (ev->mask & IN_CLOSE_WRITE)
                        synthesize_change(dev);
                else if (ev->mask & IN_IGNORED)
                        udev_watch_end(udev, dev);

                udev_device_unref(dev);
        }

        free(buf);
        return 0;
}

static void handle_signal(struct udev *udev, int signo)
{
        switch (signo) {
        case SIGINT:
        case SIGTERM:
                udev_exit = true;
                break;
        case SIGCHLD:
                for (;;) {
                        pid_t pid;
                        int status;
                        struct udev_list_node *loop, *tmp;

                        pid = waitpid(-1, &status, WNOHANG);
                        if (pid <= 0)
                                break;

                        udev_list_node_foreach_safe(loop, tmp, &worker_list) {
                                struct worker *worker = node_to_worker(loop);

                                if (worker->pid != pid)
                                        continue;
                                log_debug("worker [%u] exit", pid);

                                if (WIFEXITED(status)) {
                                        if (WEXITSTATUS(status) != 0)
                                                log_error("worker [%u] exit with return code %i",
                                                          pid, WEXITSTATUS(status));
                                } else if (WIFSIGNALED(status)) {
                                        log_error("worker [%u] terminated by signal %i (%s)",
                                                  pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                                } else if (WIFSTOPPED(status)) {
                                        log_error("worker [%u] stopped", pid);
                                } else if (WIFCONTINUED(status)) {
                                        log_error("worker [%u] continued", pid);
                                } else {
                                        log_error("worker [%u] exit with status 0x%04x", pid, status);
                                }

                                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                                        if (worker->event) {
                                                log_error("worker [%u] failed while handling '%s'",
                                                          pid, worker->event->devpath);
                                                worker->event->exitcode = -32;
                                                event_queue_delete(worker->event);

                                                /* drop reference taken for state 'running' */
                                                worker_unref(worker);
                                        }
                                }
                                worker_unref(worker);
                                break;
                        }
                }
                break;
        case SIGHUP:
                reload = true;
                break;
        }
}

static int systemd_fds(struct udev *udev, int *rctrl, int *rnetlink)
{
        int ctrl = -1, netlink = -1;
        int fd, n;

        n = sd_listen_fds(true);
        if (n <= 0)
                return -1;

        for (fd = SD_LISTEN_FDS_START; fd < n + SD_LISTEN_FDS_START; fd++) {
                if (sd_is_socket(fd, AF_LOCAL, SOCK_SEQPACKET, -1)) {
                        if (ctrl >= 0)
                                return -1;
                        ctrl = fd;
                        continue;
                }

                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1)) {
                        if (netlink >= 0)
                                return -1;
                        netlink = fd;
                        continue;
                }

                return -1;
        }

        if (ctrl < 0 || netlink < 0)
                return -1;

        log_debug("ctrl=%i netlink=%i", ctrl, netlink);
        *rctrl = ctrl;
        *rnetlink = netlink;
        return 0;
}

/*
 * read the kernel commandline, in case we need to get into debug mode
 *   udev.log-priority=<level>              syslog priority
 *   udev.children-max=<number of workers>  events are fully serialized if set to 1
 *   udev.exec-delay=<number of seconds>    delay execution of every executed program
 */
static void kernel_cmdline_options(struct udev *udev)
{
        _cleanup_free_ char *line = NULL;
        char *w, *state;
        size_t l;
        int r;

        r = proc_cmdline(&line);
        if (r < 0)
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
        if (r <= 0)
                return;

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char *s, *opt;

                s = strndup(w, l);
                if (!s)
                        break;

                /* accept the same options for the initrd, prefixed with "rd." */
                if (in_initrd() && startswith(s, "rd."))
                        opt = s + 3;
                else
                        opt = s;

                if (startswith(opt, "udev.log-priority=")) {
                        int prio;

                        prio = util_log_priority(opt + 18);
                        log_set_max_level(prio);
                        udev_set_log_priority(udev, prio);
                } else if (startswith(opt, "udev.children-max=")) {
                        children_max = strtoul(opt + 18, NULL, 0);
                } else if (startswith(opt, "udev.exec-delay=")) {
                        exec_delay = strtoul(opt + 16, NULL, 0);
                }

                free(s);
        }
}

int main(int argc, char *argv[])
{
        struct udev *udev;
        sigset_t mask;
        int daemonize = false;
        int resolve_names = 1;
        static const struct option options[] = {
                { "daemon", no_argument, NULL, 'd' },
                { "debug", no_argument, NULL, 'D' },
                { "children-max", required_argument, NULL, 'c' },
                { "exec-delay", required_argument, NULL, 'e' },
                { "resolve-names", required_argument, NULL, 'N' },
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                {}
        };
        int fd_ctrl = -1;
        int fd_netlink = -1;
        int fd_worker = -1;
        struct epoll_event ep_ctrl, ep_inotify, ep_signal, ep_netlink, ep_worker;
        struct udev_ctrl_connection *ctrl_conn = NULL;
        int rc = 1;

        udev = udev_new();
        if (udev == NULL)
                goto exit;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        udev_set_log_fn(udev, udev_main_log);
        log_set_max_level(udev_get_log_priority(udev));

        log_debug("version %s", VERSION);
        label_init("/dev");

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "c:de:DtN:hV", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'd':
                        daemonize = true;
                        break;
                case 'c':
                        children_max = strtoul(optarg, NULL, 0);
                        break;
                case 'e':
                        exec_delay = strtoul(optarg, NULL, 0);
                        break;
                case 'D':
                        debug = true;
                        log_set_max_level(LOG_DEBUG);
                        udev_set_log_priority(udev, LOG_DEBUG);
                        break;
                case 'N':
                        if (streq(optarg, "early")) {
                                resolve_names = 1;
                        } else if (streq(optarg, "late")) {
                                resolve_names = 0;
                        } else if (streq(optarg, "never")) {
                                resolve_names = -1;
                        } else {
                                fprintf(stderr, "resolve-names must be early, late or never\n");
                                log_error("resolve-names must be early, late or never");
                                goto exit;
                        }
                        break;
                case 'h':
                        printf("Usage: udevd OPTIONS\n"
                               "  --daemon\n"
                               "  --debug\n"
                               "  --children-max=<maximum number of workers>\n"
                               "  --exec-delay=<seconds to wait before executing RUN=>\n"
                               "  --resolve-names=early|late|never\n"
                               "  --version\n"
                               "  --help\n"
                               "\n");
                        goto exit;
                case 'V':
                        printf("%s\n", VERSION);
                        goto exit;
                default:
                        goto exit;
                }
        }

        kernel_cmdline_options(udev);

        if (getuid() != 0) {
                fprintf(stderr, "root privileges required\n");
                log_error("root privileges required");
                goto exit;
        }

        /* set umask before creating any file/directory */
        chdir("/");
        umask(022);

        mkdir("/run/udev", 0755);

        dev_setup(NULL);

        /* before opening new files, make sure std{in,out,err} fds are in a sane state */
        if (daemonize) {
                int fd;

                fd = open("/dev/null", O_RDWR);
                if (fd >= 0) {
                        if (write(STDOUT_FILENO, 0, 0) < 0)
                                dup2(fd, STDOUT_FILENO);
                        if (write(STDERR_FILENO, 0, 0) < 0)
                                dup2(fd, STDERR_FILENO);
                        if (fd > STDERR_FILENO)
                                close(fd);
                } else {
                        fprintf(stderr, "cannot open /dev/null\n");
                        log_error("cannot open /dev/null");
                }
        }

        if (systemd_fds(udev, &fd_ctrl, &fd_netlink) >= 0) {
                /* get control and netlink socket from systemd */
                udev_ctrl = udev_ctrl_new_from_fd(udev, fd_ctrl);
                if (udev_ctrl == NULL) {
                        log_error("error taking over udev control socket");
                        rc = 1;
                        goto exit;
                }

                monitor = udev_monitor_new_from_netlink_fd(udev, "kernel", fd_netlink);
                if (monitor == NULL) {
                        log_error("error taking over netlink socket");
                        rc = 3;
                        goto exit;
                }

                /* get our own cgroup, we regularly kill everything udev has left behind */
                if (cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &udev_cgroup) < 0)
                        udev_cgroup = NULL;
        } else {
                /* open control and netlink socket */
                udev_ctrl = udev_ctrl_new(udev);
                if (udev_ctrl == NULL) {
                        fprintf(stderr, "error initializing udev control socket");
                        log_error("error initializing udev control socket");
                        rc = 1;
                        goto exit;
                }
                fd_ctrl = udev_ctrl_get_fd(udev_ctrl);

                monitor = udev_monitor_new_from_netlink(udev, "kernel");
                if (monitor == NULL) {
                        fprintf(stderr, "error initializing netlink socket\n");
                        log_error("error initializing netlink socket");
                        rc = 3;
                        goto exit;
                }
                fd_netlink = udev_monitor_get_fd(monitor);
        }

        if (udev_monitor_enable_receiving(monitor) < 0) {
                fprintf(stderr, "error binding netlink socket\n");
                log_error("error binding netlink socket");
                rc = 3;
                goto exit;
        }

        if (udev_ctrl_enable_receiving(udev_ctrl) < 0) {
                fprintf(stderr, "error binding udev control socket\n");
                log_error("error binding udev control socket");
                rc = 1;
                goto exit;
        }

        udev_monitor_set_receive_buffer_size(monitor, 128 * 1024 * 1024);

        if (daemonize) {
                pid_t pid;

                pid = fork();
                switch (pid) {
                case 0:
                        break;
                case -1:
                        log_error("fork of daemon failed: %m");
                        rc = 4;
                        goto exit;
                default:
                        rc = EXIT_SUCCESS;
                        goto exit_daemonize;
                }

                setsid();

                write_string_file("/proc/self/oom_score_adj", "-1000");
        } else {
                sd_notify(1, "READY=1");
        }

        print_kmsg("starting version " VERSION "\n");

        if (!debug) {
                int fd;

                fd = open("/dev/null", O_RDWR);
                if (fd >= 0) {
                        dup2(fd, STDIN_FILENO);
                        dup2(fd, STDOUT_FILENO);
                        dup2(fd, STDERR_FILENO);
                        close(fd);
                }
        }

        fd_inotify = udev_watch_init(udev);
        if (fd_inotify < 0) {
                fprintf(stderr, "error initializing inotify\n");
                log_error("error initializing inotify");
                rc = 4;
                goto exit;
        }
        udev_watch_restore(udev);

        /* block and listen to all signals on signalfd */
        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (fd_signal < 0) {
                fprintf(stderr, "error creating signalfd\n");
                log_error("error creating signalfd");
                rc = 5;
                goto exit;
        }

        /* unnamed socket from workers to the main daemon */
        if (socketpair(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0, worker_watch) < 0) {
                fprintf(stderr, "error creating socketpair\n");
                log_error("error creating socketpair");
                rc = 6;
                goto exit;
        }
        fd_worker = worker_watch[READ_END];

        udev_builtin_init(udev);

        rules = udev_rules_new(udev, resolve_names);
        if (rules == NULL) {
                log_error("error reading rules");
                goto exit;
        }

        memzero(&ep_ctrl, sizeof(struct epoll_event));
        ep_ctrl.events = EPOLLIN;
        ep_ctrl.data.fd = fd_ctrl;

        memzero(&ep_inotify, sizeof(struct epoll_event));
        ep_inotify.events = EPOLLIN;
        ep_inotify.data.fd = fd_inotify;

        memzero(&ep_signal, sizeof(struct epoll_event));
        ep_signal.events = EPOLLIN;
        ep_signal.data.fd = fd_signal;

        memzero(&ep_netlink, sizeof(struct epoll_event));
        ep_netlink.events = EPOLLIN;
        ep_netlink.data.fd = fd_netlink;

        memzero(&ep_worker, sizeof(struct epoll_event));
        ep_worker.events = EPOLLIN;
        ep_worker.data.fd = fd_worker;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error("error creating epoll fd: %m");
                goto exit;
        }
        if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_ctrl, &ep_ctrl) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_inotify, &ep_inotify) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_netlink, &ep_netlink) < 0 ||
            epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_worker, &ep_worker) < 0) {
                log_error("fail to add fds to epoll: %m");
                goto exit;
        }

        if (children_max <= 0) {
                cpu_set_t cpu_set;

                children_max = 8;

                if (sched_getaffinity(0, sizeof (cpu_set), &cpu_set) == 0) {
                        children_max +=  CPU_COUNT(&cpu_set) * 2;
                }
        }
        log_debug("set children_max to %u", children_max);

        rc = udev_rules_apply_static_dev_perms(rules);
        if (rc < 0)
                log_error("failed to apply permissions on static device nodes - %s", strerror(-rc));

        udev_list_node_init(&event_list);
        udev_list_node_init(&worker_list);

        for (;;) {
                static usec_t last_usec;
                struct epoll_event ev[8];
                int fdcount;
                int timeout;
                bool is_worker, is_signal, is_inotify, is_netlink, is_ctrl;
                int i;

                if (udev_exit) {
                        /* close sources of new events and discard buffered events */
                        if (fd_ctrl >= 0) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_ctrl, NULL);
                                fd_ctrl = -1;
                        }
                        if (monitor != NULL) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_netlink, NULL);
                                udev_monitor_unref(monitor);
                                monitor = NULL;
                        }
                        if (fd_inotify >= 0) {
                                epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_inotify, NULL);
                                close(fd_inotify);
                                fd_inotify = -1;
                        }

                        /* discard queued events and kill workers */
                        event_queue_cleanup(udev, EVENT_QUEUED);
                        worker_kill(udev);

                        /* exit after all has cleaned up */
                        if (udev_list_node_is_empty(&event_list) && children == 0)
                                break;

                        /* timeout at exit for workers to finish */
                        timeout = 30 * MSEC_PER_SEC;
                } else if (udev_list_node_is_empty(&event_list) && children == 0) {
                        /* we are idle */
                        timeout = -1;

                        /* cleanup possible left-over processes in our cgroup */
                        if (udev_cgroup)
                                cg_kill(SYSTEMD_CGROUP_CONTROLLER, udev_cgroup, SIGKILL, false, true, NULL);
                } else {
                        /* kill idle or hanging workers */
                        timeout = 3 * MSEC_PER_SEC;
                }

                /* tell settle that we are busy or idle */
                if (!udev_list_node_is_empty(&event_list)) {
                        int fd;

                        fd = open("/run/udev/queue", O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd >= 0)
                                close(fd);
                } else {
                        unlink("/run/udev/queue");
                }

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), timeout);
                if (fdcount < 0)
                        continue;

                if (fdcount == 0) {
                        struct udev_list_node *loop;

                        /* timeout */
                        if (udev_exit) {
                                log_error("timeout, giving up waiting for workers to finish");
                                break;
                        }

                        /* kill idle workers */
                        if (udev_list_node_is_empty(&event_list)) {
                                log_debug("cleanup idle workers");
                                worker_kill(udev);
                        }

                        /* check for hanging events */
                        udev_list_node_foreach(loop, &worker_list) {
                                struct worker *worker = node_to_worker(loop);

                                if (worker->state != WORKER_RUNNING)
                                        continue;

                                if ((now(CLOCK_MONOTONIC) - worker->event_start_usec) > 30 * USEC_PER_SEC) {
                                        log_error("worker [%u] %s timeout; kill it", worker->pid,
                                            worker->event ? worker->event->devpath : "<idle>");
                                        kill(worker->pid, SIGKILL);
                                        worker->state = WORKER_KILLED;

                                        /* drop reference taken for state 'running' */
                                        worker_unref(worker);
                                        if (worker->event) {
                                                log_error("seq %llu '%s' killed", udev_device_get_seqnum(worker->event->dev), worker->event->devpath);
                                                worker->event->exitcode = -64;
                                                event_queue_delete(worker->event);
                                                worker->event = NULL;
                                        }
                                }
                        }

                }

                is_worker = is_signal = is_inotify = is_netlink = is_ctrl = false;
                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_worker && ev[i].events & EPOLLIN)
                                is_worker = true;
                        else if (ev[i].data.fd == fd_netlink && ev[i].events & EPOLLIN)
                                is_netlink = true;
                        else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN)
                                is_signal = true;
                        else if (ev[i].data.fd == fd_inotify && ev[i].events & EPOLLIN)
                                is_inotify = true;
                        else if (ev[i].data.fd == fd_ctrl && ev[i].events & EPOLLIN)
                                is_ctrl = true;
                }

                /* check for changed config, every 3 seconds at most */
                if ((now(CLOCK_MONOTONIC) - last_usec) > 3 * USEC_PER_SEC) {
                        if (udev_rules_check_timestamp(rules))
                                reload = true;
                        if (udev_builtin_validate(udev))
                                reload = true;

                        last_usec = now(CLOCK_MONOTONIC);
                }

                /* reload requested, HUP signal received, rules changed, builtin changed */
                if (reload) {
                        worker_kill(udev);
                        rules = udev_rules_unref(rules);
                        udev_builtin_exit(udev);
                        reload = false;
                }

                /* event has finished */
                if (is_worker)
                        worker_returned(fd_worker);

                if (is_netlink) {
                        struct udev_device *dev;

                        dev = udev_monitor_receive_device(monitor);
                        if (dev != NULL) {
                                udev_device_set_usec_initialized(dev, now(CLOCK_MONOTONIC));
                                if (event_queue_insert(dev) < 0)
                                        udev_device_unref(dev);
                        }
                }

                /* start new events */
                if (!udev_list_node_is_empty(&event_list) && !udev_exit && !stop_exec_queue) {
                        udev_builtin_init(udev);
                        if (rules == NULL)
                                rules = udev_rules_new(udev, resolve_names);
                        if (rules != NULL)
                                event_queue_start(udev);
                }

                if (is_signal) {
                        struct signalfd_siginfo fdsi;
                        ssize_t size;

                        size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size == sizeof(struct signalfd_siginfo))
                                handle_signal(udev, fdsi.ssi_signo);
                }

                /* we are shutting down, the events below are not handled anymore */
                if (udev_exit)
                        continue;

                /* device node watch */
                if (is_inotify)
                        handle_inotify(udev);

                /*
                 * This needs to be after the inotify handling, to make sure,
                 * that the ping is send back after the possibly generated
                 * "change" events by the inotify device node watch.
                 *
                 * A single time we may receive a client connection which we need to
                 * keep open to block the client. It will be closed right before we
                 * exit.
                 */
                if (is_ctrl)
                        ctrl_conn = handle_ctrl_msg(udev_ctrl);
        }

        rc = EXIT_SUCCESS;
exit:
        udev_ctrl_cleanup(udev_ctrl);
        unlink("/run/udev/queue");
exit_daemonize:
        if (fd_ep >= 0)
                close(fd_ep);
        worker_list_cleanup(udev);
        event_queue_cleanup(udev, EVENT_UNDEF);
        udev_rules_unref(rules);
        udev_builtin_exit(udev);
        if (fd_signal >= 0)
                close(fd_signal);
        if (worker_watch[READ_END] >= 0)
                close(worker_watch[READ_END]);
        if (worker_watch[WRITE_END] >= 0)
                close(worker_watch[WRITE_END]);
        udev_monitor_unref(monitor);
        udev_ctrl_connection_unref(ctrl_conn);
        udev_ctrl_unref(udev_ctrl);
        label_finish();
        udev_unref(udev);
        log_close();
        return rc;
}
