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
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev-util.h"
#include "udev-watch.h"

int device_new_from_watch_handle_at(sd_device **ret, int dirfd, int wd) {
        char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *id = NULL;
        int r;

        assert(ret);

        if (wd < 0)
                return -EBADF;

        if (dirfd >= 0) {
                xsprintf(path_wd, "%d", wd);
                r = readlinkat_malloc(dirfd, path_wd, &id);
        } else {
                xsprintf(path_wd, "/run/udev/watch/%d", wd);
                r = readlink_malloc(path_wd, &id);
        }
        if (r < 0)
                return r;

        return sd_device_new_from_device_id(ret, id);
}

int udev_watch_restore(int inotify_fd) {
        _cleanup_closedir_ DIR *dir = NULL;
        int r;

        /* Move any old watches directory out of the way, and then restore the watches. */

        assert(inotify_fd >= 0);

        (void) rm_rf("/run/udev/watch.old", REMOVE_ROOT);

        if (rename("/run/udev/watch", "/run/udev/watch.old") < 0) {
                if (errno == ENOENT)
                        return 0;

                r = log_warning_errno(errno,
                                      "Failed to move watches directory '/run/udev/watch/'. "
                                      "Old watches will not be restored: %m");
                goto finalize;
        }

        dir = opendir("/run/udev/watch.old");
        if (!dir) {
                r = log_warning_errno(errno,
                                      "Failed to open old watches directory '/run/udev/watch.old/'. "
                                      "Old watches will not be restored: %m");
                goto finalize;
        }

        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                int wd;

                /* For backward compatibility, read symlink from watch handle to device ID. This is necessary
                 * when udevd is restarted after upgrading from v248 or older. The new format (ID -> wd) was
                 * introduced by e7f781e473f5119bf9246208a6de9f6b76a39c5d (v249). */

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (safe_atoi(de->d_name, &wd) < 0)
                        continue;

                r = device_new_from_watch_handle_at(&dev, dirfd(dir), wd);
                if (r < 0) {
                        log_full_errno(r == -ENODEV ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to create sd_device object from saved watch handle '%i', ignoring: %m",
                                       wd);
                        continue;
                }

                (void) udev_watch_begin(inotify_fd, dev);
        }

        r = 0;

finalize:
        (void) rm_rf("/run/udev/watch.old", REMOVE_ROOT);
        return r;
}

static int udev_watch_clear(sd_device *dev, int dirfd, int *ret_wd) {
        _cleanup_free_ char *wd_str = NULL, *buf = NULL;
        const char *id;
        int wd = -1, r;

        assert(dev);
        assert(dirfd >= 0);

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        /* 1. read symlink ID -> wd */
        r = readlinkat_malloc(dirfd, id, &wd_str);
        if (r == -ENOENT) {
                if (ret_wd)
                        *ret_wd = -1;
                return 0;
        }
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        r = safe_atoi(wd_str, &wd);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to parse watch handle from symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        if (wd < 0) {
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(EBADF), "Invalid watch handle %i.", wd);
                goto finalize;
        }

        /* 2. read symlink wd -> ID */
        r = readlinkat_malloc(dirfd, wd_str, &buf);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read symlink '/run/udev/watch/%s': %m", wd_str);
                goto finalize;
        }

        /* 3. check if the symlink wd -> ID is owned by the device. */
        if (!streq(buf, id)) {
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOENT),
                                           "Symlink '/run/udev/watch/%s' is owned by another device '%s'.", wd_str, buf);
                goto finalize;
        }

        /* 4. remove symlink wd -> ID.
         * In the above, we already confirmed that the symlink is owned by us. Hence, no other workers remove
         * the symlink and cannot create a new symlink with the same filename but to a different ID. Hence,
         * the removal below is safe even the steps in this function are not atomic. */
        if (unlinkat(dirfd, wd_str, 0) < 0 && errno != ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s', ignoring: %m", wd_str);

        if (ret_wd)
                *ret_wd = wd;
        r = 0;

finalize:
        /* 5. remove symlink ID -> wd.
         * The file is always owned by the device. Hence, it is safe to remove it unconditionally. */
        if (unlinkat(dirfd, id, 0) < 0 && errno != ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s': %m", id);

        return r;
}

int udev_watch_begin(int inotify_fd, sd_device *dev) {
        char wd_str[DECIMAL_STR_MAX(int)];
        _cleanup_close_ int dirfd = -EBADF;
        const char *devnode, *id;
        int wd, r;

        assert(inotify_fd >= 0);
        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return 0;

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        r = dirfd = open_mkdir_at(AT_FDCWD, "/run/udev/watch", O_CLOEXEC | O_RDONLY, 0755);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to create and open '/run/udev/watch/': %m");

        /* 1. Clear old symlinks */
        (void) udev_watch_clear(dev, dirfd, NULL);

        /* 2. Add inotify watch */
        log_device_debug(dev, "Adding watch on '%s'", devnode);
        wd = inotify_add_watch(inotify_fd, devnode, IN_CLOSE_WRITE);
        if (wd < 0)
                return log_device_debug_errno(dev, errno, "Failed to watch device node '%s': %m", devnode);

        xsprintf(wd_str, "%d", wd);

        /* 3. Create new symlinks */
        if (symlinkat(wd_str, dirfd, id) < 0) {
                r = log_device_debug_errno(dev, errno, "Failed to create symlink '/run/udev/watch/%s' to '%s': %m", id, wd_str);
                goto on_failure;
        }

        if (symlinkat(id, dirfd, wd_str) < 0) {
                /* Possibly, the watch handle is previously assigned to another device, and udev_watch_end()
                 * is not called for the device yet. */
                r = log_device_debug_errno(dev, errno, "Failed to create symlink '/run/udev/watch/%s' to '%s': %m", wd_str, id);
                goto on_failure;
        }

        return 0;

on_failure:
        (void) unlinkat(dirfd, id, 0);
        (void) inotify_rm_watch(inotify_fd, wd);
        return r;
}

int udev_watch_end(int inotify_fd, sd_device *dev) {
        _cleanup_close_ int dirfd = -EBADF;
        int wd, r;

        assert(inotify_fd >= 0);
        assert(dev);

        if (sd_device_get_devname(dev, NULL) < 0)
                return 0;

        dirfd = RET_NERRNO(open("/run/udev/watch", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY));
        if (dirfd == -ENOENT)
                return 0;
        if (dirfd < 0)
                return log_device_debug_errno(dev, dirfd, "Failed to open '/run/udev/watch/': %m");

        /* First, clear symlinks. */
        r = udev_watch_clear(dev, dirfd, &wd);
        if (r < 0)
                return r;

        /* Then, remove inotify watch. */
        log_device_debug(dev, "Removing watch handle %i.", wd);
        (void) inotify_rm_watch(inotify_fd, wd);

        return 0;
}
