/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <sys/inotify.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "stdio-util.h"
#include "udev-watch.h"

/* Move any old watches directory out of the way, and then restore the watches. */
int udev_watch_restore(int inotify_fd) {
        struct dirent *ent;
        DIR *dir;
        int r;

        assert(inotify_fd >= 0);

        if (rename("/run/udev/watch", "/run/udev/watch.old") < 0) {
                if (errno != ENOENT)
                        return log_warning_errno(errno, "Failed to move watches directory /run/udev/watch. Old watches will not be restored: %m");

                return 0;
        }

        dir = opendir("/run/udev/watch.old");
        if (!dir)
                return log_warning_errno(errno, "Failed to open old watches directory /run/udev/watch.old. Old watches will not be restored: %m");

        FOREACH_DIRENT_ALL(ent, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                _cleanup_free_ char *id = NULL;

                if (ent->d_name[0] == '.')
                        continue;

                r = readlinkat_malloc(dirfd(dir), ent->d_name, &id);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read link '/run/udev/watch.old/%s', ignoring: %m", ent->d_name);
                        goto unlink;
                }

                r = sd_device_new_from_device_id(&dev, id);
                if (r < 0) {
                        log_debug_errno(r, "Failed to create sd_device object for '%s', ignoring: %m", id);
                        goto unlink;
                }

                log_device_debug(dev, "Restoring old watch");
                (void) udev_watch_begin(inotify_fd, dev);
unlink:
                (void) unlinkat(dirfd(dir), ent->d_name, 0);
        }

        (void) closedir(dir);
        (void) rmdir("/run/udev/watch.old");

        return 0;
}

int udev_watch_begin(int inotify_fd, sd_device *dev) {
        char filename[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        const char *devnode, *id;
        int wd, r;

        assert(inotify_fd >= 0);
        assert(dev);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get device name: %m");

        log_device_debug(dev, "Adding watch on '%s'", devnode);
        wd = inotify_add_watch(inotify_fd, devnode, IN_CLOSE_WRITE);
        if (wd < 0)
                return log_device_full_errno(dev, errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                             "Failed to add device '%s' to watch: %m", devnode);

        device_set_watch_handle(dev, wd);

        xsprintf(filename, "/run/udev/watch/%d", wd);
        r = mkdir_parents(filename, 0755);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to create parent directory of '%s': %m", filename);
        (void) unlink(filename);

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get device id-filename: %m");

        if (symlink(id, filename) < 0)
                return log_device_error_errno(dev, errno, "Failed to create symlink %s: %m", filename);

        return 0;
}

int udev_watch_end(int inotify_fd, sd_device *dev) {
        char filename[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        int wd, r;

        assert(dev);

        /* This may be called by 'udevadm test'. In that case, inotify_fd is not initialized. */
        if (inotify_fd < 0)
                return 0;

        if (sd_device_get_devname(dev, NULL) < 0)
                return 0;

        r = device_get_watch_handle(dev, &wd);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get watch handle, ignoring: %m");

        log_device_debug(dev, "Removing watch");
        (void) inotify_rm_watch(inotify_fd, wd);

        xsprintf(filename, "/run/udev/watch/%d", wd);
        (void) unlink(filename);

        device_set_watch_handle(dev, -1);

        return 0;
}

int udev_watch_lookup(int wd, sd_device **ret) {
        char filename[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *id = NULL;
        int r;

        assert(wd >= 0);
        assert(ret);

        xsprintf(filename, "/run/udev/watch/%d", wd);
        r = readlink_malloc(filename, &id);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to read link '%s': %m", filename);

        r = sd_device_new_from_device_id(ret, id);
        if (r == -ENODEV)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to create sd_device object for '%s': %m", id);

        return 1;
}
