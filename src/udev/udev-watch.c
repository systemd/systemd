/*
 * Copyright (C) 2004-2012 Kay Sievers <kay@vrfy.org>
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

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "udev.h"

static int inotify_fd = -1;

/* inotify descriptor, will be shared with rules directory;
 * set to cloexec since we need our children to be able to add
 * watches for us
 */
int udev_watch_init(struct udev *udev) {
        inotify_fd = inotify_init1(IN_CLOEXEC);
        if (inotify_fd < 0)
                log_error_errno(errno, "inotify_init failed: %m");
        return inotify_fd;
}

/* move any old watches directory out of the way, and then restore
 * the watches
 */
void udev_watch_restore(struct udev *udev) {
        if (inotify_fd < 0)
                return;

        if (rename("/run/udev/watch", "/run/udev/watch.old") == 0) {
                DIR *dir;
                struct dirent *ent;

                dir = opendir("/run/udev/watch.old");
                if (dir == NULL) {
                        log_error_errno(errno, "unable to open old watches dir /run/udev/watch.old; old watches will not be restored: %m");
                        return;
                }

                for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
                        char device[UTIL_PATH_SIZE];
                        ssize_t len;
                        struct udev_device *dev;

                        if (ent->d_name[0] == '.')
                                continue;

                        len = readlinkat(dirfd(dir), ent->d_name, device, sizeof(device));
                        if (len <= 0 || len == (ssize_t)sizeof(device))
                                goto unlink;
                        device[len] = '\0';

                        dev = udev_device_new_from_device_id(udev, device);
                        if (dev == NULL)
                                goto unlink;

                        log_debug("restoring old watch on '%s'", udev_device_get_devnode(dev));
                        udev_watch_begin(udev, dev);
                        udev_device_unref(dev);
unlink:
                        unlinkat(dirfd(dir), ent->d_name, 0);
                }

                closedir(dir);
                rmdir("/run/udev/watch.old");

        } else if (errno != ENOENT)
                log_error_errno(errno, "unable to move watches dir /run/udev/watch; old watches will not be restored: %m");
}

void udev_watch_begin(struct udev *udev, struct udev_device *dev) {
        char filename[UTIL_PATH_SIZE];
        int wd;
        int r;

        if (inotify_fd < 0)
                return;

        log_debug("adding watch on '%s'", udev_device_get_devnode(dev));
        wd = inotify_add_watch(inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
        if (wd < 0) {
                log_error_errno(errno, "inotify_add_watch(%d, %s, %o) failed: %m",
                                inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
                return;
        }

        snprintf(filename, sizeof(filename), "/run/udev/watch/%d", wd);
        mkdir_parents(filename, 0755);
        unlink(filename);
        r = symlink(udev_device_get_id_filename(dev), filename);
        if (r < 0)
                log_error_errno(errno, "Failed to create symlink %s: %m", filename);

        udev_device_set_watch_handle(dev, wd);
}

void udev_watch_end(struct udev *udev, struct udev_device *dev) {
        int wd;
        char filename[UTIL_PATH_SIZE];

        if (inotify_fd < 0)
                return;

        wd = udev_device_get_watch_handle(dev);
        if (wd < 0)
                return;

        log_debug("removing watch on '%s'", udev_device_get_devnode(dev));
        inotify_rm_watch(inotify_fd, wd);

        snprintf(filename, sizeof(filename), "/run/udev/watch/%d", wd);
        unlink(filename);

        udev_device_set_watch_handle(dev, -1);
}

struct udev_device *udev_watch_lookup(struct udev *udev, int wd) {
        char filename[UTIL_PATH_SIZE];
        char device[UTIL_NAME_SIZE];
        ssize_t len;

        if (inotify_fd < 0 || wd < 0)
                return NULL;

        snprintf(filename, sizeof(filename), "/run/udev/watch/%d", wd);
        len = readlink(filename, device, sizeof(device));
        if (len <= 0 || (size_t)len == sizeof(device))
                return NULL;
        device[len] = '\0';

        return udev_device_new_from_device_id(udev, device);
}
