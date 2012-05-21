/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Harald Hoyer, Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"
#include "path-util.h"
#include "switch-root.h"

int switch_root(const char *new_root) {

        /*  Don't try to unmount/move the old "/", there's no way to do it. */
        static const char move_mounts[] =
                "/dev\0"
                "/proc\0"
                "/sys\0"
                "/run\0";

        int r, old_root_fd = -1;
        struct stat new_root_stat;
        bool old_root_remove;
        const char *i;

        if (path_equal(new_root, "/"))
                return 0;

        old_root_remove = in_initrd();

        if (stat(new_root, &new_root_stat) < 0) {
                r = -errno;
                log_error("Failed to stat directory %s: %m", new_root);
                goto fail;
        }

        NULSTR_FOREACH(i, move_mounts) {
                char new_mount[PATH_MAX];
                struct stat sb;

                snprintf(new_mount, sizeof(new_mount), "%s%s", new_root, i);
                char_array_0(new_mount);

                if ((stat(new_mount, &sb) < 0) ||
                    sb.st_dev != new_root_stat.st_dev) {

                        /* Mount point seems to be mounted already or
                         * stat failed. Unmount the old mount
                         * point. */
                        if (umount2(i, MNT_DETACH) < 0)
                                log_warning("Failed to unmount %s: %m", i);
                        continue;
                }

                if (mount(i, new_mount, NULL, MS_MOVE, NULL) < 0) {
                        log_error("Failed to move mount %s to %s, forcing unmount: %m", i, new_mount);

                        if (umount2(i, MNT_FORCE) < 0)
                                log_warning("Failed to unmount %s: %m", i);
                }
        }

        if (chdir(new_root) < 0) {
                r = -errno;
                log_error("Failed to change directory to %s: %m", new_root);
                goto fail;
        }

        if (old_root_remove) {
                old_root_fd = open("/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (old_root_fd < 0)
                        log_warning("Failed to open root directory: %m");
        }

        if (mount(new_root, "/", NULL, MS_MOVE, NULL) < 0) {
                r = -errno;
                log_error("Failed to mount moving %s to /: %m", new_root);
                goto fail;
        }

        if (chroot(".") < 0) {
                r = -errno;
                log_error("Failed to change root: %m");
                goto fail;
        }

        if (old_root_fd >= 0) {
                struct stat rb;

                if (fstat(old_root_fd, &rb) < 0)
                        log_warning("Failed to stat old root directory, leaving: %m");
                else
                        rm_rf_children(old_root_fd, false, false, &rb);
        }

        r = 0;

fail:
        if (old_root_fd >= 0)
                close_nointr_nofail(old_root_fd);

        return r;
}
