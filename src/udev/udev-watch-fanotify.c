/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <sys/fanotify.h>
#include <unistd.h>

#include "daemon-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fanotify-util.h"
#include "fd-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "udev-manager.h"
#include "udev-synth.h"
#include "udev-util.h"
#include "udev-watch.h"
#include "udev-worker.h"

static int device_watch(int fanotify_fd, sd_device *dev, bool add) {
        assert(fanotify_fd >= 0);
        assert(dev);

        _cleanup_close_ int fd = sd_device_open(dev, O_CLOEXEC | O_NOFOLLOW | O_PATH);
        if (fd < 0)
                return fd;

        return fanotify_mark_fd(
                        fanotify_fd,
                        (add ? FAN_MARK_ADD : FAN_MARK_REMOVE) | FAN_MARK_INODE,
                        FAN_CLOSE_WRITE,
                        fd);
}

static int manager_process_fanotify(Manager *manager, const struct fanotify_event_metadata *e) {
        int r;

        assert(manager);
        assert(e);

        if (!FLAGS_SET(e->mask, FAN_CLOSE_WRITE))
                return 0;

        _cleanup_close_ int fd = fanotify_event_open_by_fid(e, manager->dev_fd, &manager->dev_statfs);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to get file descriptor from fanotify event, ignoring: %m");

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_device_node_fd(&dev, fd);
        if (r < 0) /* Device may be removed just after closed. */
                return log_debug_errno(r, "Failed to resolve device from file descriptor obtained by fanotify event, ignoring: %m");

        log_device_debug(dev, "Received fanotify close-after-write event.");

        (void) manager_create_queue_file(manager);
        (void) manager_requeue_locked_events_by_device(manager, dev);
        (void) manager_synthesize_change(manager, dev);
        return 0;
}

static int on_fanotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(fd >= 0);

        union fanotify_event_buffer buffer;
        ssize_t l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read fanotify events: %m");
        }

        bool overflow = false;
        FOREACH_FANOTIFY_EVENT(e, buffer, l) {
                if (e->vers != FANOTIFY_METADATA_VERSION)
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTO),
                                               "fanotify metadata version mismatch (got %u, expected %u).",
                                               e->vers, (unsigned) FANOTIFY_METADATA_VERSION);

                (void) manager_process_fanotify(manager, e);

                if (FLAGS_SET(e->mask, FAN_Q_OVERFLOW))
                        overflow = true;
        }
        if (overflow)
                log_debug("fanotify event queue overflow detected, some close events might be dropped.");

        return 0;
}

static int udev_watch_restore(Manager *manager) {
        _cleanup_(rm_rf_safep) const char *old = "/run/udev/watch.old/";
        int r;

        /* Migrate watches registered by an older, inotify-based udevd, which stored them as symlinks under
         * /run/udev/watch/. Re-add them as fanotify marks, then drop the directory: the fanotify
         * implementation does not use it. Downgrading back to inotify is not supported; after a downgrade,
         * re-enabling the watches requires running 'udevadm trigger' for all devices that have a device node. */

        assert(manager);
        assert(manager->fanotify_fd >= 0);

        rm_rf_safe(old);
        if (rename("/run/udev/watch/", old) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to move watches directory '/run/udev/watch/': %m");
        }

        _cleanup_closedir_ DIR *dir = opendir(old);
        if (!dir)
                return log_warning_errno(errno, "Failed to open old watches directory '%s': %m", old);

        FOREACH_DIRENT(de, dir, break) {
                if (in_charset(de->d_name, DIGITS))
                        continue; /* This should be wd -> ID symlink. Skipping. */

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                r = sd_device_new_from_device_id(&dev, de->d_name);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_NEG_DEVICE_ABSENT(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to create sd_device object from device ID '%s', ignoring: %m",
                                       de->d_name);
                        continue;
                }

                r = device_watch(manager->fanotify_fd, dev, /* add= */ true);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to add device watch, ignoring: %m");
        }

        return 0;
}

int manager_init_fanotify(Manager *manager, int fd) {
        int r;

        assert(manager);

        /* This takes passed file descriptor on success. */

        r = secure_getenv_bool("SYSTEMD_UDEV_USE_INOTIFY");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_UDEV_USE_INOTIFY, ignoring: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Using inotify for device watch (as requested by $SYSTEMD_UDEV_USE_INOTIFY).");

        if (manager->dev_fd < 0) {
                _cleanup_close_ int dev_fd = open("/dev/", O_CLOEXEC | O_DIRECTORY);
                if (dev_fd < 0)
                        return log_error_errno(errno, "Failed to open '/dev/': %m");

                if (fstatfs(dev_fd, &manager->dev_statfs) < 0)
                        return log_error_errno(errno, "Failed to statfs '/dev/': %m");

                /* fanotify can only watch device nodes via FAN_REPORT_FID (file handle mode). FAN_REPORT_FID
                 * requires both non-zero f_fsid and file handle support; devtmpfs provides these only when
                 * backed by tmpfs on kernels ≥ v5.13 (see commit 59cda49ecf6c9a32fae4942420701b6e087204f6).
                 * On older kernels, or when CONFIG_SHMEM=n (making devtmpfs use ramfs instead), device watch
                 * falls back to inotify. */
                if (memeqzero(&manager->dev_statfs.f_fsid, sizeof(manager->dev_statfs.f_fsid)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "The kernel does not support fanotify for device nodes, falling back to use inotify.");

                manager->dev_fd = TAKE_FD(dev_fd);
        }

        if (fd >= 0) {
                if (manager->fanotify_fd >= 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple fanotify fd (%i), ignoring.", fd);

                log_debug("Received fanotify fd (%i) from service manager.", fd);
                manager->fanotify_fd = fd;
                return 0;
        }

        if (manager->fanotify_fd >= 0)
                return 0;

        fd = fanotify_init(
                        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID,
                        O_CLOEXEC | O_NONBLOCK | O_RDONLY);
        if (fd < 0) {
                /* CONFIG_FANOTIFY is disabled. */
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_debug_errno(errno, "Failed to create fanotify group, falling back to use inotify: %m");

                return log_error_errno(errno, "Failed to create fanotify group: %m");
        }

        log_debug("Initialized new fanotify group.");
        manager->fanotify_fd = fd;
        (void) udev_watch_restore(manager);

        r = notify_push_fd(manager->fanotify_fd, "fanotify");
        if (r < 0)
                log_warning_errno(r, "Failed to push fanotify fd to service manager, ignoring: %m");
        else
                log_debug("Pushed fanotify fd to service manager.");

        return 0;
}

int manager_start_fanotify(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        r = manager_init_fanotify(manager, -EBADF);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(manager->event, &s, manager->fanotify_fd, EPOLLIN, on_fanotify, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create event source for device watch: %m");

        r = sd_event_source_set_priority(s, EVENT_PRIORITY_DEVICE_WATCH);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority to event source for device watch: %m");

        (void) sd_event_source_set_description(s, "manager-device-watch");

        manager->device_watch_event = TAKE_PTR(s);
        return 0;
}

void udev_watch_begin(UdevWorker *worker, sd_device *dev) {
        int r;

        assert(worker);
        assert(dev);

        if (worker->fanotify_fd < 0)
                return inotify_watch_begin(worker, dev);

        /* Ignore the request of watching the device node on remove event, as the device node specified by
         * DEVNAME= has already been removed, and may already be assigned to another device. Consider the
         * case e.g. a USB stick memory was unplugged and then another one is plugged. */
        if (device_for_action(dev, SD_DEVICE_REMOVE)) {
                log_device_debug(dev, "Ignoring to add device watch on remove uevent.");
                return;
        }

        r = device_watch(worker->fanotify_fd, dev, /* add= */ true);
        if (r == -ENOEXEC)
                return; /* The device does not have device node. */
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to add device watch, ignoring: %m");
        else
                log_device_debug(dev, "Added device watch.");
}

void udev_watch_end(UdevWorker *worker, sd_device *dev) {
        int r;

        assert(worker);
        assert(dev);

        if (worker->fanotify_fd < 0)
                return inotify_watch_end(worker, dev);

        r = device_watch(worker->fanotify_fd, dev, /* add= */ false);
        if (IN_SET(r, -ENOEXEC, -ENOENT))
                /* ENOEXEC : The device does not have device node. */
                /* ENOENT  : The node is not watched, or the device node is already gone. */
                return;
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to remove device watch, ignoring: %m");
        else
                log_device_debug(dev, "Removed device watch.");
}
