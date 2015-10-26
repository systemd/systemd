/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "btrfs-util.h"
#include "fd-util.h"
#include "mount-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "util.h"

int rm_rf_children(int fd, RemoveFlags flags, struct stat *root_dev) {
        _cleanup_closedir_ DIR *d = NULL;
        int ret = 0, r;

        assert(fd >= 0);

        /* This returns the first error we run into, but nevertheless
         * tries to go on. This closes the passed fd. */

        if (!(flags & REMOVE_PHYSICAL)) {

                r = fd_is_temporary_fs(fd);
                if (r < 0) {
                        safe_close(fd);
                        return r;
                }

                if (!r) {
                        /* We refuse to clean physical file systems
                         * with this call, unless explicitly
                         * requested. This is extra paranoia just to
                         * be sure we never ever remove non-state
                         * data */

                        log_error("Attempted to remove disk file system, and we can't allow that.");
                        safe_close(fd);
                        return -EPERM;
                }
        }

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return errno == ENOENT ? 0 : -errno;
        }

        for (;;) {
                struct dirent *de;
                bool is_dir;
                struct stat st;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno != 0 && ret == 0)
                                ret = -errno;
                        return ret;
                }

                if (streq(de->d_name, ".") || streq(de->d_name, ".."))
                        continue;

                if (de->d_type == DT_UNKNOWN ||
                    (de->d_type == DT_DIR && (root_dev || (flags & REMOVE_SUBVOLUME)))) {
                        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        is_dir = S_ISDIR(st.st_mode);
                } else
                        is_dir = de->d_type == DT_DIR;

                if (is_dir) {
                        int subdir_fd;

                        /* if root_dev is set, remove subdirectories only if device is same */
                        if (root_dev && st.st_dev != root_dev->st_dev)
                                continue;

                        subdir_fd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                        if (subdir_fd < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        /* Stop at mount points */
                        r = fd_is_mount_point(fd, de->d_name, 0);
                        if (r < 0) {
                                if (ret == 0 && r != -ENOENT)
                                        ret = r;

                                safe_close(subdir_fd);
                                continue;
                        }
                        if (r) {
                                safe_close(subdir_fd);
                                continue;
                        }

                        if ((flags & REMOVE_SUBVOLUME) && st.st_ino == 256) {

                                /* This could be a subvolume, try to remove it */

                                r = btrfs_subvol_remove_fd(fd, de->d_name, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                                if (r < 0) {
                                        if (r != -ENOTTY && r != -EINVAL) {
                                                if (ret == 0)
                                                        ret = r;

                                                safe_close(subdir_fd);
                                                continue;
                                        }

                                        /* ENOTTY, then it wasn't a
                                         * btrfs subvolume, continue
                                         * below. */
                                } else {
                                        /* It was a subvolume, continue. */
                                        safe_close(subdir_fd);
                                        continue;
                                }
                        }

                        /* We pass REMOVE_PHYSICAL here, to avoid
                         * doing the fstatfs() to check the file
                         * system type again for each directory */
                        r = rm_rf_children(subdir_fd, flags | REMOVE_PHYSICAL, root_dev);
                        if (r < 0 && ret == 0)
                                ret = r;

                        if (unlinkat(fd, de->d_name, AT_REMOVEDIR) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                        }

                } else if (!(flags & REMOVE_ONLY_DIRECTORIES)) {

                        if (unlinkat(fd, de->d_name, 0) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                        }
                }
        }
}

int rm_rf(const char *path, RemoveFlags flags) {
        int fd, r;
        struct statfs s;

        assert(path);

        /* We refuse to clean the root file system with this
         * call. This is extra paranoia to never cause a really
         * seriously broken system. */
        if (path_equal(path, "/")) {
                log_error("Attempted to remove entire root file system, and we can't allow that.");
                return -EPERM;
        }

        if ((flags & (REMOVE_SUBVOLUME|REMOVE_ROOT|REMOVE_PHYSICAL)) == (REMOVE_SUBVOLUME|REMOVE_ROOT|REMOVE_PHYSICAL)) {
                /* Try to remove as subvolume first */
                r = btrfs_subvol_remove(path, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                if (r >= 0)
                        return r;

                if (r != -ENOTTY && r != -EINVAL && r != -ENOTDIR)
                        return r;

                /* Not btrfs or not a subvolume */
        }

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0) {

                if (errno != ENOTDIR && errno != ELOOP)
                        return -errno;

                if (!(flags & REMOVE_PHYSICAL)) {
                        if (statfs(path, &s) < 0)
                                return -errno;

                        if (!is_temporary_fs(&s)) {
                                log_error("Attempted to remove disk file system, and we can't allow that.");
                                return -EPERM;
                        }
                }

                if ((flags & REMOVE_ROOT) && !(flags & REMOVE_ONLY_DIRECTORIES))
                        if (unlink(path) < 0 && errno != ENOENT)
                                return -errno;

                return 0;
        }

        r = rm_rf_children(fd, flags, NULL);

        if (flags & REMOVE_ROOT) {
                if (rmdir(path) < 0) {
                        if (r == 0 && errno != ENOENT)
                                r = -errno;
                }
        }

        return r;
}
