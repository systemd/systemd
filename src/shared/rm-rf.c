/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"

/* We treat tmpfs/ramfs + cgroupfs as non-physical file systems. cgroupfs is similar to tmpfs in a way
 * after all: we can create arbitrary directory hierarchies in it, and hence can also use rm_rf() on it
 * to remove those again. */
static bool is_physical_fs(const struct statfs *sfs) {
        return !is_temporary_fs(sfs) && !is_cgroup_fs(sfs);
}

static int patch_dirfd_mode(
                int dfd,
                mode_t *ret_old_mode) {

        struct stat st;

        assert(dfd >= 0);
        assert(ret_old_mode);

        if (fstat(dfd, &st) < 0)
                return -errno;
        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;
        if (FLAGS_SET(st.st_mode, 0700)) /* Already set? */
                return -EACCES; /* original error */
        if (st.st_uid != geteuid())  /* this only works if the UID matches ours */
                return -EACCES;

        if (fchmod(dfd, (st.st_mode | 0700) & 07777) < 0)
                return -errno;

        *ret_old_mode = st.st_mode;
        return 0;
}

int unlinkat_harder(int dfd, const char *filename, int unlink_flags, RemoveFlags remove_flags) {

        mode_t old_mode;
        int r;

        /* Like unlinkat(), but tries harder: if we get EACCESS we'll try to set the r/w/x bits on the
         * directory. This is useful if we run unprivileged and have some files where the w bit is
         * missing. */

        if (unlinkat(dfd, filename, unlink_flags) >= 0)
                return 0;
        if (errno != EACCES || !FLAGS_SET(remove_flags, REMOVE_CHMOD))
                return -errno;

        r = patch_dirfd_mode(dfd, &old_mode);
        if (r < 0)
                return r;

        if (unlinkat(dfd, filename, unlink_flags) < 0) {
                r = -errno;
                /* Try to restore the original access mode if this didn't work */
                (void) fchmod(dfd, old_mode);
                return r;
        }

        if (FLAGS_SET(remove_flags, REMOVE_CHMOD_RESTORE) && fchmod(dfd, old_mode) < 0)
                return -errno;

        /* If this worked, we won't reset the old mode by default, since we'll need it for other entries too,
         * and we should destroy the whole thing */
        return 0;
}

int fstatat_harder(int dfd,
                const char *filename,
                struct stat *ret,
                int fstatat_flags,
                RemoveFlags remove_flags) {

        mode_t old_mode;
        int r;

        /* Like unlink_harder() but does the same for fstatat() */

        if (fstatat(dfd, filename, ret, fstatat_flags) >= 0)
                return 0;
        if (errno != EACCES || !FLAGS_SET(remove_flags, REMOVE_CHMOD))
                return -errno;

        r = patch_dirfd_mode(dfd, &old_mode);
        if (r < 0)
                return r;

        if (fstatat(dfd, filename, ret, fstatat_flags) < 0) {
                r = -errno;
                (void) fchmod(dfd, old_mode);
                return r;
        }

        if (FLAGS_SET(remove_flags, REMOVE_CHMOD_RESTORE) && fchmod(dfd, old_mode) < 0)
                return -errno;

        return 0;
}

static int rm_rf_children_inner(
                int fd,
                const char *fname,
                int is_dir,
                RemoveFlags flags,
                const struct stat *root_dev) {

        struct stat st;
        int r, q = 0;

        assert(fd >= 0);
        assert(fname);

        if (is_dir < 0 ||
            root_dev ||
            (is_dir > 0 && (root_dev || (flags & REMOVE_SUBVOLUME)))) {

                r = fstatat_harder(fd, fname, &st, AT_SYMLINK_NOFOLLOW, flags);
                if (r < 0)
                        return r;

                is_dir = S_ISDIR(st.st_mode);
        }

        if (is_dir) {
                _cleanup_close_ int subdir_fd = -1;

                /* if root_dev is set, remove subdirectories only if device is same */
                if (root_dev && st.st_dev != root_dev->st_dev)
                        return 0;

                /* Stop at mount points */
                r = fd_is_mount_point(fd, fname, 0);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                if ((flags & REMOVE_SUBVOLUME) && btrfs_might_be_subvol(&st)) {

                        /* This could be a subvolume, try to remove it */

                        r = btrfs_subvol_remove_fd(fd, fname, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                        if (r < 0) {
                                if (!IN_SET(r, -ENOTTY, -EINVAL))
                                        return r;

                                /* ENOTTY, then it wasn't a btrfs subvolume, continue below. */
                        } else
                                /* It was a subvolume, done. */
                                return 1;
                }

                subdir_fd = openat(fd, fname, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                if (subdir_fd < 0)
                        return -errno;

                /* We pass REMOVE_PHYSICAL here, to avoid doing the fstatfs() to check the file system type
                 * again for each directory */
                q = rm_rf_children(TAKE_FD(subdir_fd), flags | REMOVE_PHYSICAL, root_dev);

        } else if (flags & REMOVE_ONLY_DIRECTORIES)
                return 0;

        r = unlinkat_harder(fd, fname, is_dir ? AT_REMOVEDIR : 0, flags);
        if (r < 0)
                return r;
        if (q < 0)
                return q;
        return 1;
}

int rm_rf_children(
                int fd,
                RemoveFlags flags,
                const struct stat *root_dev) {

        _cleanup_closedir_ DIR *d = NULL;
        int ret = 0, r;

        assert(fd >= 0);

        /* This returns the first error we run into, but nevertheless tries to go on. This closes the passed
         * fd, in all cases, including on failure. */

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        if (!(flags & REMOVE_PHYSICAL)) {
                struct statfs sfs;

                if (fstatfs(dirfd(d), &sfs) < 0)
                        return -errno;

                if (is_physical_fs(&sfs)) {
                        /* We refuse to clean physical file systems with this call, unless explicitly
                         * requested. This is extra paranoia just to be sure we never ever remove non-state
                         * data. */

                        _cleanup_free_ char *path = NULL;

                        (void) fd_get_path(fd, &path);
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                               "Attempted to remove disk file system under \"%s\", and we can't allow that.",
                                               strna(path));
                }
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                int is_dir;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                is_dir =
                        de->d_type == DT_UNKNOWN ? -1 :
                        de->d_type == DT_DIR;

                r = rm_rf_children_inner(dirfd(d), de->d_name, is_dir, flags, root_dev);
                if (r < 0 && r != -ENOENT && ret == 0)
                        ret = r;
        }

        if (FLAGS_SET(flags, REMOVE_SYNCFS) && syncfs(dirfd(d)) < 0 && ret >= 0)
                ret = -errno;

        return ret;
}

int rm_rf(const char *path, RemoveFlags flags) {
        int fd, r;

        assert(path);

        /* For now, don't support dropping subvols when also only dropping directories, since we can't do
         * this race-freely. */
        if (FLAGS_SET(flags, REMOVE_ONLY_DIRECTORIES|REMOVE_SUBVOLUME))
                return -EINVAL;

        /* We refuse to clean the root file system with this call. This is extra paranoia to never cause a
         * really seriously broken system. */
        if (path_equal_or_files_same(path, "/", AT_SYMLINK_NOFOLLOW))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Attempted to remove entire root file system (\"%s\"), and we can't allow that.",
                                       path);

        if (FLAGS_SET(flags, REMOVE_SUBVOLUME | REMOVE_ROOT | REMOVE_PHYSICAL)) {
                /* Try to remove as subvolume first */
                r = btrfs_subvol_remove(path, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                if (r >= 0)
                        return r;

                if (FLAGS_SET(flags, REMOVE_MISSING_OK) && r == -ENOENT)
                        return 0;

                if (!IN_SET(r, -ENOTTY, -EINVAL, -ENOTDIR))
                        return r;

                /* Not btrfs or not a subvolume */
        }

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0) {
                if (FLAGS_SET(flags, REMOVE_MISSING_OK) && errno == ENOENT)
                        return 0;

                if (!IN_SET(errno, ENOTDIR, ELOOP))
                        return -errno;

                if (FLAGS_SET(flags, REMOVE_ONLY_DIRECTORIES))
                        return 0;

                if (FLAGS_SET(flags, REMOVE_ROOT)) {

                        if (!FLAGS_SET(flags, REMOVE_PHYSICAL)) {
                                struct statfs s;

                                if (statfs(path, &s) < 0)
                                        return -errno;
                                if (is_physical_fs(&s))
                                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                               "Attempted to remove files from a disk file system under \"%s\", refusing.",
                                                               path);
                        }

                        if (unlink(path) < 0) {
                                if (FLAGS_SET(flags, REMOVE_MISSING_OK) && errno == ENOENT)
                                        return 0;

                                return -errno;
                        }
                }

                return 0;
        }

        r = rm_rf_children(fd, flags, NULL);

        if (FLAGS_SET(flags, REMOVE_ROOT) &&
            rmdir(path) < 0 &&
            r >= 0 &&
            (!FLAGS_SET(flags, REMOVE_MISSING_OK) || errno != ENOENT))
                r = -errno;

        return r;
}

int rm_rf_child(int fd, const char *name, RemoveFlags flags) {

        /* Removes one specific child of the specified directory */

        if (fd < 0)
                return -EBADF;

        if (!filename_is_valid(name))
                return -EINVAL;

        if ((flags & (REMOVE_ROOT|REMOVE_MISSING_OK)) != 0) /* Doesn't really make sense here, we are not supposed to remove 'fd' anyway */
                return -EINVAL;

        if (FLAGS_SET(flags, REMOVE_ONLY_DIRECTORIES|REMOVE_SUBVOLUME))
                return -EINVAL;

        return rm_rf_children_inner(fd, name, -1, flags, NULL);
}
