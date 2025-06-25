/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/fs.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-netlink.h"

#include "blockdev-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "process-util.h"
#include "udev-error.h"
#include "udev-event.h"
#include "udev-rules.h"
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
}

int udev_get_whole_disk(sd_device *dev, sd_device **ret_device, const char **ret_devname) {
        const char *val;
        int r;

        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                goto irrelevant;

        /* Exclude the following devices:
         * For "dm-", see the comment added by e918a1b5a94f270186dca59156354acd2a596494.
         * For "md", see the commit message of 2e5b17d01347d3c3118be2b8ad63d20415dbb1f0,
         * but not sure the assumption is still valid even when partitions are created on the md
         * devices, surprisingly which seems to be possible, see PR #22973.
         * For "drbd", see the commit message of fee854ee8ccde0cd28e0f925dea18cce35f3993d. */
        r = device_sysname_startswith(dev, "dm-", "md", "drbd");
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check sysname: %m");
        if (r > 0)
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

static int worker_lock_whole_disk(UdevWorker *worker, sd_device *dev, int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        sd_device *dev_whole_disk;
        const char *whole_disk;
        int r;

        assert(worker);
        assert(dev);
        assert(ret_fd);

        /* Take a shared lock on the device node; this establishes a concept of device "ownership" to
         * serialize device access. External processes holding an exclusive lock will cause udev to skip the
         * event handling; in the case udev acquired the lock, the external process can block until udev has
         * finished its event handling. */

        /* Do not try to lock device on remove event, as the device node specified by DEVNAME= has already
         * been removed, and may already be assigned to another device. Consider the case e.g. a USB stick
         * memory was unplugged and then another one is plugged. */
        if (device_for_action(dev, SD_DEVICE_REMOVE))
                goto nolock;

        r = udev_get_whole_disk(dev, &dev_whole_disk, &whole_disk);
        if (r < 0)
                return r;
        if (r == 0)
                goto nolock;

        fd = sd_device_open(dev_whole_disk, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT(fd);

                log_device_debug_errno(dev, fd, "Failed to open '%s'%s: %m", whole_disk, ignore ? ", ignoring" : "");
                if (!ignore)
                        return fd;

                goto nolock;
        }

        if (flock(fd, LOCK_SH|LOCK_NB) < 0) {
                if (errno != EAGAIN)
                        return log_device_debug_errno(dev, errno, "Failed to flock(%s): %m", whole_disk);

                log_device_debug_errno(dev, errno, "Block device %s is currently locked, requeuing the event.", whole_disk);

                r = sd_notifyf(/* unset_environment = */ false, "TRY_AGAIN=1\nWHOLE_DISK=%s", whole_disk);
                if (r < 0) {
                        log_device_warning_errno(dev, r, "Failed to send notification message to manager process: %m");
                        (void) sd_event_exit(worker->event, r);
                }

                return -EAGAIN;
        }

        log_device_debug(dev, "Successfully took flock(LOCK_SH) for %s, it will be released after the event has been processed.", whole_disk);
        *ret_fd = TAKE_FD(fd);
        return 1;

nolock:
        *ret_fd = -EBADF;
        return 0;
}

static int worker_mark_block_device_read_only(sd_device *dev) {
        int r;

        assert(dev);

        /* Do this only once, when the block device is new. If the device is later retriggered let's not
         * toggle the bit again, so that people can boot up with full read-only mode and then unset the bit
         * for specific devices only. */
        if (!device_for_action(dev, SD_DEVICE_ADD))
                return 0;

        r = device_in_subsystem(dev, "block");
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        /* Exclude synthetic devices for now, this is supposed to be a safety feature to avoid modification
         * of physical devices, and what sits on top of those doesn't really matter if we don't allow the
         * underlying block devices to receive changes. */
        r = device_sysname_startswith(dev, "dm-", "md", "drbd", "loop", "nbd", "zram");
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check sysname: %m");
        if (r > 0)
                return 0;

        const char *val;
        r = sd_device_get_devname(dev, &val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        _cleanup_close_ int fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_device_debug_errno(dev, fd, "Failed to open '%s', ignoring: %m", val);

        int state = 1;
        if (ioctl(fd, BLKROSET, &state) < 0)
                return log_device_warning_errno(dev, errno, "Failed to mark block device '%s' read-only: %m", val);

        log_device_info(dev, "Successfully marked block device '%s' read-only.", val);
        return 0;
}

static int worker_process_device(UdevWorker *worker, sd_device *dev) {
        int r;

        assert(worker);
        assert(dev);

        log_device_uevent(dev, "Processing device");

        /* If this is a block device and the device is locked currently via the BSD advisory locks,
         * someone else is using it exclusively. We don't run our udev rules now to not interfere.
         * Instead of processing the event, we requeue the event and will try again after a delay.
         *
         * The user-facing side of this: https://systemd.io/BLOCK_DEVICE_LOCKING */
        _cleanup_close_ int fd_lock = -EBADF;
        r = worker_lock_whole_disk(worker, dev, &fd_lock);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        if (worker->config.blockdev_read_only)
                (void) worker_mark_block_device_read_only(dev);

        /* Disable watch during event processing. */
        r = udev_watch_end(worker, dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to remove inotify watch, ignoring: %m");

        _cleanup_(udev_event_unrefp) UdevEvent *udev_event = udev_event_new(dev, worker, EVENT_UDEV_WORKER);
        if (!udev_event)
                return -ENOMEM;
        udev_event->trace = worker->config.trace;

        /* apply rules, create node, symlinks */
        r = udev_event_execute_rules(udev_event, worker->rules);
        if (r < 0)
                return r;

        /* Process RUN=. */
        udev_event_execute_run(udev_event);

        if (!worker->rtnl)
                /* in case rtnl was initialized */
                worker->rtnl = sd_netlink_ref(udev_event->rtnl);

        /* Enable watch if requested. */
        if (udev_event->inotify_watch) {
                r = udev_watch_begin(worker, dev);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to add inotify watch, ignoring: %m");
        }

        /* Finalize database. But do not re-create database on remove, which has been already removed in
         * event_execute_rules_on_remove(). */
        if (!device_for_action(dev, SD_DEVICE_REMOVE)) {
                r = device_add_property(dev, "ID_PROCESSING", NULL);
                if (r < 0)
                        return log_device_warning_errno(dev, r, "Failed to remove 'ID_PROCESSING' property: %m");

                r = device_update_db(dev);
                if (r < 0)
                        return log_device_warning_errno(dev, r, "Failed to update database under /run/udev/data/: %m");
        }

        log_device_uevent(dev, "Device processed");

        /* send processed event to libudev listeners */
        r = device_monitor_send(worker->monitor, NULL, dev);
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to broadcast event to libudev listeners: %m");
                (void) sd_event_exit(worker->event, r);
                return 0;
        }

        r = sd_notify(/* unset_environment = */ false, "PROCESSED=1");
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to send notification message to manager process: %m");
                (void) sd_event_exit(worker->event, r);
        }

        return 0;
}

static int worker_device_monitor_handler(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        UdevWorker *worker = ASSERT_PTR(userdata);
        int r;

        assert(monitor);
        assert(dev);

        r = worker_process_device(worker, dev);
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to process device, ignoring: %m");
                (void) device_add_errno(dev, r);

                /* broadcast (possibly partially processed) event to libudev listeners */
                int k = device_monitor_send(monitor, NULL, dev);
                if (k < 0) {
                        log_device_warning_errno(dev, k, "Failed to broadcast event to libudev listeners: %m");
                        (void) sd_event_exit(worker->event, k);
                        return 0;
                }

                const char *e = errno_to_name(r);
                r = sd_notifyf(/* unset_environment = */ false, "ERRNO=%i%s%s", -r, e ? "\nERRNO_NAME=" : "", strempty(e));
                if (r < 0) {
                        log_device_warning_errno(dev, r, "Failed to send notification message to manager process, ignoring: %m");
                        (void) sd_event_exit(worker->event, r);
                        return 0;
                }
        }

        /* Reset the log level, as it might be changed by "OPTIONS=log_level=". */
        log_set_max_level(worker->config.log_level);

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
