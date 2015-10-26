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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base-filesystem.h"
#include "fd-util.h"
#include "missing.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "switch-root.h"
#include "user-util.h"
#include "util.h"

int switch_root(const char *new_root, const char *oldroot, bool detach_oldroot,  unsigned long mountflags) {

        /*  Don't try to unmount/move the old "/", there's no way to do it. */
        static const char move_mounts[] =
                "/dev\0"
                "/proc\0"
                "/sys\0"
                "/run\0";

        _cleanup_close_ int old_root_fd = -1;
        struct stat new_root_stat;
        bool old_root_remove;
        const char *i, *temporary_old_root;

        if (path_equal(new_root, "/"))
                return 0;

        temporary_old_root = strjoina(new_root, oldroot);
        mkdir_p_label(temporary_old_root, 0755);

        old_root_remove = in_initrd();

        if (stat(new_root, &new_root_stat) < 0)
                return log_error_errno(errno, "Failed to stat directory %s: %m", new_root);

        /* Work-around for kernel design: the kernel refuses switching
         * root if any file systems are mounted MS_SHARED. Hence
         * remount them MS_PRIVATE here as a work-around.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=847418 */
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
                log_warning_errno(errno, "Failed to make \"/\" private mount: %m");

        NULSTR_FOREACH(i, move_mounts) {
                char new_mount[PATH_MAX];
                struct stat sb;

                snprintf(new_mount, sizeof(new_mount), "%s%s", new_root, i);

                mkdir_p_label(new_mount, 0755);

                if ((stat(new_mount, &sb) < 0) ||
                    sb.st_dev != new_root_stat.st_dev) {

                        /* Mount point seems to be mounted already or
                         * stat failed. Unmount the old mount
                         * point. */
                        if (umount2(i, MNT_DETACH) < 0)
                                log_warning_errno(errno, "Failed to unmount %s: %m", i);
                        continue;
                }

                if (mount(i, new_mount, NULL, mountflags, NULL) < 0) {
                        if (mountflags & MS_MOVE) {
                                log_error_errno(errno, "Failed to move mount %s to %s, forcing unmount: %m", i, new_mount);

                                if (umount2(i, MNT_FORCE) < 0)
                                        log_warning_errno(errno, "Failed to unmount %s: %m", i);
                        }
                        if (mountflags & MS_BIND)
                                log_error_errno(errno, "Failed to bind mount %s to %s: %m", i, new_mount);

                }
        }

        /* Do not fail, if base_filesystem_create() fails. Not all
         * switch roots are like base_filesystem_create() wants them
         * to look like. They might even boot, if they are RO and
         * don't have the FS layout. Just ignore the error and
         * switch_root() nevertheless. */
        (void) base_filesystem_create(new_root, UID_INVALID, GID_INVALID);

        if (chdir(new_root) < 0)
                return log_error_errno(errno, "Failed to change directory to %s: %m", new_root);

        if (old_root_remove) {
                old_root_fd = open("/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (old_root_fd < 0)
                        log_warning_errno(errno, "Failed to open root directory: %m");
        }

        /* We first try a pivot_root() so that we can umount the old
         * root dir. In many cases (i.e. where rootfs is /), that's
         * not possible however, and hence we simply overmount root */
        if (pivot_root(new_root, temporary_old_root) >= 0) {

                /* Immediately get rid of the old root, if detach_oldroot is set.
                 * Since we are running off it we need to do this lazily. */
                if (detach_oldroot && umount2(oldroot, MNT_DETACH) < 0)
                        log_error_errno(errno, "Failed to lazily umount old root dir %s, %s: %m",
                                  oldroot,
                                  errno == ENOENT ? "ignoring" : "leaving it around");

        } else if (mount(new_root, "/", NULL, MS_MOVE, NULL) < 0)
                return log_error_errno(errno, "Failed to mount moving %s to /: %m", new_root);

        if (chroot(".") < 0)
                return log_error_errno(errno, "Failed to change root: %m");

        if (chdir("/") < 0)
                return log_error_errno(errno, "Failed to change directory: %m");

        if (old_root_fd >= 0) {
                struct stat rb;

                if (fstat(old_root_fd, &rb) < 0)
                        log_warning_errno(errno, "Failed to stat old root directory, leaving: %m");
                else {
                        (void) rm_rf_children(old_root_fd, 0, &rb);
                        old_root_fd = -1;
                }
        }

        return 0;
}
