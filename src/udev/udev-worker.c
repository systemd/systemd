/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "common-signal.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "udev-event.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-watch.h"
#include "udev-worker.h"

void udev_worker_done(UdevWorker *worker) {
        assert(worker);

        sd_event_unref(worker->event);
        sd_netlink_unref(worker->rtnl);
        sd_device_monitor_unref(worker->monitor);
        hashmap_free(worker->properties);
        udev_rules_free(worker->rules);
        safe_close(worker->pipe_fd);
}

int udev_get_whole_disk(sd_device *dev, sd_device **ret_device, const char **ret_devname) {
        const char *val;
        int r;

        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                goto irrelevant;

        r = sd_device_get_sysname(dev, &val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        /* Exclude the following devices:
         * For "dm-", see the comment added by e918a1b5a94f270186dca59156354acd2a596494.
         * For "md", see the commit message of 2e5b17d01347d3c3118be2b8ad63d20415dbb1f0,
         * but not sure the assumption is still valid even when partitions are created on the md
         * devices, surprisingly which seems to be possible, see PR #22973.
         * For "drbd", see the commit message of fee854ee8ccde0cd28e0f925dea18cce35f3993d. */
        if (STARTSWITH_SET(val, "dm-", "md", "drbd"))
                goto irrelevant;

        r = block_device_get_whole_disk(dev, &dev);
        if (IN_SET(r,
                   -ENOTBLK, /* The device is not a block device. */
                   -ENODEV   /* The whole disk device was not found, it may already be removed. */))
                goto irrelevant;
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get whole disk device: %m");

        r = sd_device_get_devname(dev, &val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devname: %m");

        if (ret_device)
                *ret_device = dev;
        if (ret_devname)
                *ret_devname = val;
        return 1;

irrelevant:
        if (ret_device)
                *ret_device = NULL;
        if (ret_devname)
                *ret_devname = NULL;
        return 0;
}

static int worker_lock_whole_disk(sd_device *dev, int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        sd_device *dev_whole_disk;
        const char *val;
        int r;

        assert(dev);
        assert(ret_fd);

        /* Take a shared lock on the device node; this establishes a concept of device "ownership" to
         * serialize device access. External processes holding an exclusive lock will cause udev to skip the
         * event handling; in the case udev acquired the lock, the external process can block until udev has
         * finished its event handling. */

        r = udev_get_whole_disk(dev, &dev_whole_disk, &val);
        if (r < 0)
                return r;
        if (r == 0)
                goto nolock;

        fd = sd_device_open(dev_whole_disk, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT(fd);

                log_device_debug_errno(dev, fd, "Failed to open '%s'%s: %m", val, ignore ? ", ignoring" : "");
                if (!ignore)
                        return fd;

                goto nolock;
        }

        if (flock(fd, LOCK_SH|LOCK_NB) < 0)
                return log_device_debug_errno(dev, errno, "Failed to flock(%s): %m", val);

        *ret_fd = TAKE_FD(fd);
        return 1;

nolock:
        *ret_fd = -EBADF;
        return 0;
}

static int worker_mark_block_device_read_only(sd_device *dev) {
        _cleanup_close_ int fd = -EBADF;
        const char *val;
        int state = 1, r;

        assert(dev);

        /* Do this only once, when the block device is new. If the device is later retriggered let's not
         * toggle the bit again, so that people can boot up with full read-only mode and then unset the bit
         * for specific devices only. */
        if (!device_for_action(dev, SD_DEVICE_ADD))
                return 0;

        r = sd_device_get_subsystem(dev, &val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get subsystem: %m");

        if (!streq(val, "block"))
                return 0;

        r = sd_device_get_sysname(dev, &val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        /* Exclude synthetic devices for now, this is supposed to be a safety feature to avoid modification
         * of physical devices, and what sits on top of those doesn't really matter if we don't allow the
         * underlying block devices to receive changes. */
        if (STARTSWITH_SET(val, "dm-", "md", "drbd", "loop", "nbd", "zram"))
                return 0;

        fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_device_debug_errno(dev, fd, "Failed to open '%s', ignoring: %m", val);

        if (ioctl(fd, BLKROSET, &state) < 0)
                return log_device_warning_errno(dev, errno, "Failed to mark block device '%s' read-only: %m", val);

        log_device_info(dev, "Successfully marked block device '%s' read-only.", val);
        return 0;
}

static int worker_process_device(UdevWorker *worker, sd_device *dev) {
        _cleanup_(udev_event_freep) UdevEvent *udev_event = NULL;
        _cleanup_close_ int fd_lock = -EBADF;
        int r;

        assert(worker);
        assert(dev);

        log_device_uevent(dev, "Processing device");

        udev_event = udev_event_new(dev, worker->exec_delay_usec, worker->rtnl, worker->log_level);
        if (!udev_event)
                return -ENOMEM;

        /* If this is a block device and the device is locked currently via the BSD advisory locks,
         * someone else is using it exclusively. We don't run our udev rules now to not interfere.
         * Instead of processing the event, we requeue the event and will try again after a delay.
         *
         * The user-facing side of this: https://systemd.io/BLOCK_DEVICE_LOCKING */
        r = worker_lock_whole_disk(dev, &fd_lock);
        if (r == -EAGAIN)
                return EVENT_RESULT_TRY_AGAIN;
        if (r < 0)
                return r;

        if (worker->blockdev_read_only)
                (void) worker_mark_block_device_read_only(dev);

        /* Disable watch during event processing. */
        r = udev_watch_end(worker->inotify_fd, dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to remove inotify watch, ignoring: %m");

        /* apply rules, create node, symlinks */
        r = udev_event_execute_rules(
                          udev_event,
                          worker->timeout_usec,
                          worker->timeout_signal,
                          worker->properties,
                          worker->rules);
        if (r < 0)
                return r;

        udev_event_execute_run(udev_event, worker->timeout_usec, worker->timeout_signal);

        if (!worker->rtnl)
                /* in case rtnl was initialized */
                worker->rtnl = sd_netlink_ref(udev_event->rtnl);

        if (udev_event->inotify_watch) {
                r = udev_watch_begin(worker->inotify_fd, dev);
                if (r < 0 && r != -ENOENT) /* The device may be already removed, ignore -ENOENT. */
                        log_device_warning_errno(dev, r, "Failed to add inotify watch, ignoring: %m");
        }

        log_device_uevent(dev, "Device processed");
        return 0;
}

void udev_broadcast_result(sd_device_monitor *monitor, sd_device *dev, EventResult result) {
        int r;

        assert(dev);

        /* On exit, manager->monitor is already NULL. */
        if (!monitor)
                return;

        if (result != EVENT_RESULT_SUCCESS) {
                (void) device_add_property(dev, "UDEV_WORKER_FAILED", "1");

                switch (result) {
                case EVENT_RESULT_NERRNO_MIN ... EVENT_RESULT_NERRNO_MAX: {
                        const char *str;

                        (void) device_add_propertyf(dev, "UDEV_WORKER_ERRNO", "%i", -result);

                        str = errno_to_name(result);
                        if (str)
                                (void) device_add_property(dev, "UDEV_WORKER_ERRNO_NAME", str);
                        break;
                }
                case EVENT_RESULT_EXIT_STATUS_BASE ... EVENT_RESULT_EXIT_STATUS_MAX:
                        (void) device_add_propertyf(dev, "UDEV_WORKER_EXIT_STATUS", "%i", result - EVENT_RESULT_EXIT_STATUS_BASE);
                        break;

                case EVENT_RESULT_TRY_AGAIN:
                        assert_not_reached();
                        break;

                case EVENT_RESULT_SIGNAL_BASE ... EVENT_RESULT_SIGNAL_MAX: {
                        const char *str;

                        (void) device_add_propertyf(dev, "UDEV_WORKER_SIGNAL", "%i", result - EVENT_RESULT_SIGNAL_BASE);

                        str = signal_to_string(result - EVENT_RESULT_SIGNAL_BASE);
                        if (str)
                                (void) device_add_property(dev, "UDEV_WORKER_SIGNAL_NAME", str);
                        break;
                }
                default:
                        log_device_warning(dev, "Unknown event result \"%i\", ignoring.", result);
                }
        }

        r = device_monitor_send_device(monitor, NULL, dev);
        if (r < 0)
                log_device_warning_errno(dev, r,
                                         "Failed to broadcast event to libudev listeners, ignoring: %m");
}

static int worker_send_result(UdevWorker *worker, EventResult result) {
        assert(worker);
        assert(worker->pipe_fd >= 0);

        return loop_write(worker->pipe_fd, &result, sizeof(result));
}

static int worker_device_monitor_handler(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        UdevWorker *worker = ASSERT_PTR(userdata);
        int r;

        assert(dev);

        r = worker_process_device(worker, dev);
        if (r == EVENT_RESULT_TRY_AGAIN)
                /* if we couldn't acquire the flock(), then requeue the event */
                log_device_debug(dev, "Block device is currently locked, requeueing the event.");
        else {
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to process device, ignoring: %m");

                /* send processed event back to libudev listeners */
                udev_broadcast_result(monitor, dev, r);
        }

        /* send udevd the result of the event execution */
        r = worker_send_result(worker, r);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to send signal to main daemon, ignoring: %m");

        /* Reset the log level, as it might be changed by "OPTIONS=log_level=". */
        log_set_max_level(worker->log_level);

        return 1;
}

int udev_worker_main(UdevWorker *worker, sd_device *dev) {
        int r;

        assert(worker);
        assert(worker->monitor);
        assert(dev);

        DEVICE_TRACE_POINT(worker_spawned, dev, getpid_cached());

        /* Reset OOM score, we only protect the main daemon. */
        r = set_oom_score_adjust(0);
        if (r < 0)
                log_debug_errno(r, "Failed to reset OOM score, ignoring: %m");

        r = sd_event_new(&worker->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_signal(worker->event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set SIGTERM event: %m");

        r = sd_device_monitor_attach_event(worker->monitor, worker->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event loop to device monitor: %m");

        r = sd_device_monitor_start(worker->monitor, worker_device_monitor_handler, worker);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        /* Process first device */
        (void) worker_device_monitor_handler(worker->monitor, dev, worker);

        r = sd_event_loop(worker->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
