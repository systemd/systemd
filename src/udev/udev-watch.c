/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <sys/inotify.h>

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev-watch.h"

int device_new_from_watch_handle(sd_device **ret, int wd) {
        _cleanup_closedir_ DIR *dir = NULL;
        char wd_str[DECIMAL_STR_MAX(int)];

        assert(ret);

        /* At the time this function is called, there exist the following possibilities:
         * A. No matching symlink exists. This happens (A-1) when the watch handle is assigned to a
         *    device, but it has not been saved to a symlink yet. Or (A-2) the device is already
         *    removed and the corresponding 'remove' uevent is already processed or being processed.
         * B. A wrong symlink exists. This happens when a device, which the watch handle was previously
         *    assigned to, has been already removed, but the corresponding 'remove' uevent has not been
         *    processed yet. And the watch handle has been already assigned to another device.
         *
         * So, in the worst case, there exist multiple symlinks for each watch handle. However, even in
         * such case, for each device handle, there exists at most one symlink from the device ID
         * corresponds to a *existing* device. See also comments in udev_watch_end(). Hence, in the
         * below, it is OK to return the first device obtained by sd_device_new_from_device_id().
         *
         * Of course, there exists another worst case that there exists no symlink to point the
         * requested watch handle. That is, the case A in the above. But, the case A-2 does not cause
         * any issue, as the device does not exist anymore. Unfortunately, the case A-1 cannot be
         * salvaged. But the timespan of A-1 should be small enough. Moreover, when we process a block
         * device, we lock its backing whole block device (except for some special kind of devices such
         * as MD devices). Hence, applications which follow our advisory
         * https://systemd.io/BLOCK_DEVICE_LOCKING do not trigger such inotify events. And, usually,
         * no character device is watched. */

        if (wd < 0)
                return -EBADF;

        xsprintf(wd_str, "%d", wd);

        dir = opendir("/run/udev/watch");
        if (!dir)
                return -errno;

        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                _cleanup_free_ char *buf = NULL;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (readlinkat_malloc(dirfd(dir), de->d_name, &buf) < 0)
                        continue;

                if (!streq(buf, wd_str))
                        continue;

                if (sd_device_new_from_device_id(&dev, de->d_name) >= 0) {
                        *ret = TAKE_PTR(dev);
                        return 0;
                }
        }

        return -ENOENT;
}

static int udev_watch_restore_one(int inotify_fd, const char *id) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(inotify_fd >= 0);
        assert(id);

        r = sd_device_new_from_device_id(&dev, id);
        if (r < 0)
                return log_full_errno(r == -ENODEV ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to create sd_device object from device ID '%s', ignoring: %m",
                                      id);

        r = udev_watch_begin(inotify_fd, dev);
        if (r < 0 && r != -ENOENT)
                return log_device_warning_errno(dev, r, "Failed to restore watching device node, ignoring: %m");

        return 0;
}

int udev_watch_restore(int inotify_fd) {
        bool has_new_format = false;
        DIR *dir;
        int r;

        /* Move any old watches directory out of the way, and then restore the watches. */

        assert(inotify_fd >= 0);

        if (rename("/run/udev/watch", "/run/udev/watch.old") < 0) {
                if (errno != ENOENT)
                        return log_warning_errno(errno,
                                                 "Failed to move watches directory /run/udev/watch. "
                                                 "Old watches will not be restored: %m");

                return 0;
        }

        dir = opendir("/run/udev/watch.old");
        if (!dir) {
                r = log_warning_errno(errno,
                                      "Failed to open old watches directory /run/udev/watch.old. "
                                      "Old watches will not be restored: %m");

                (void) rm_rf("/run/udev/watch.old", REMOVE_ROOT);
                return r;
        }

        FOREACH_DIRENT_ALL(de, dir, break) {
                if (dot_or_dot_dot(de->d_name))
                        continue;

                /* First, read symlink from device ID to watch handle.
                 * This is a new format since e7f781e473f5119bf9246208a6de9f6b76a39c5d (v249). */

                if (in_charset(de->d_name, DIGITS))
                        continue;

                has_new_format = true;

                (void) udev_watch_restore_one(inotify_fd, de->d_name);
        }

        if (has_new_format)
                goto finalize;

        rewinddir(dir);
        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_free_ char *id = NULL;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                /* For backward compatibility, read symlink from watch handle to device ID. This is
                 * necessary when udevd is restarted after upgrading from v248 or older. */

                if (!in_charset(de->d_name, DIGITS))
                        continue;

                if (readlinkat_malloc(dirfd(dir), de->d_name, &id) < 0)
                        continue;

                (void) udev_watch_restore_one(inotify_fd, id);
        }

finalize:
        (void) closedir(dir);
        (void) rm_rf("/run/udev/watch.old", REMOVE_ROOT);

        return 0;
}

int udev_watch_begin(int inotify_fd, sd_device *dev) {
        char wd_str[DECIMAL_STR_MAX(int)];
        _cleanup_close_ int fd = -1;
        const char *devnode, *id;
        int wd, r;

        assert(inotify_fd >= 0);
        assert(dev);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        r = mkdir_p("/run/udev/watch", 0755);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to create /run/udev/watch: %m");

        fd = open("/run/udev/watch", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
        if (fd < 0)
                return log_device_debug_errno(dev, errno, "Failed to open /run/udev/watch: %m");

        if (unlinkat(fd, id, 0) < 0 && errno != -ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s', ignoring: %m", id);

        log_device_debug(dev, "Adding watch on '%s'", devnode);
        wd = inotify_add_watch(inotify_fd, devnode, IN_CLOSE_WRITE);
        if (wd < 0)
                return log_device_debug_errno(dev, errno, "Failed to watch device node '%s': %m", devnode);

        xsprintf(wd_str, "%d", wd);

        if (symlinkat(wd_str, fd, id) < 0) {
                r = log_device_debug_errno(dev, errno, "Failed to create symlink '/run/udev/watch/%s' to '%s': %m", id, wd_str);
                (void) inotify_rm_watch(inotify_fd, wd);
                return r;
        }

        return 0;
}

int udev_watch_end(int inotify_fd, sd_device *dev) {
        _cleanup_free_ char *wd_str = NULL;
        _cleanup_close_ int fd = -1;
        const char *id;
        int wd = -1, r;

        assert(dev);

        /* This may be called by 'udevadm test'. In that case, inotify_fd is not initialized. */
        if (inotify_fd < 0)
                return 0;

        if (sd_device_get_devname(dev, NULL) < 0)
                return 0;

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        fd = RET_NERRNO(open("/run/udev/watch", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY));
        if (fd == -ENOENT)
                return 0;
        if (fd < 0)
                return log_device_debug_errno(dev, fd, "Failed to open /run/udev/watch: %m");

        r = readlinkat_malloc(fd, id, &wd_str);
        if (r == -ENOENT)
                return 0;
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        r = safe_atoi(wd_str, &wd);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to parse watch handle from symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        if (wd < 0)
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(EBADF), "Invalid watch handle %i.", wd);

        r = 0;

finalize:
        /* Here, first remove the symlink. Otherwise, the watch handle may be reused by another worker,
         * and multiple symlinks from IDs of existing devices to the same watch handle may exist. That
         * causes device_new_from_watch_handle() returns a wrong device. Also see the comments in
         * device_new_from_watch_handle(). */

        if (unlinkat(fd, id, 0) < 0 && errno != -ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s', ignoring: %m", id);

        if (wd >= 0) {
                log_device_debug(dev, "Removing watch handle %i.", wd);
                (void) inotify_rm_watch(inotify_fd, wd);
        }

        return r;
}
