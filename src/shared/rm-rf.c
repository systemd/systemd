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

static int rm_rf_inner_child(
                int fd,
                const char *fname,
                int is_dir,
                RemoveFlags flags,
                const struct stat *root_dev,
                bool allow_recursion) {

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
                /* If root_dev is set, remove subdirectories only if device is same */
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

                if (!allow_recursion)
                        return -EISDIR;

                int subdir_fd = openat(fd, fname, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                if (subdir_fd < 0)
                        return -errno;

                /* We pass REMOVE_PHYSICAL here, to avoid doing the fstatfs() to check the file system type
                 * again for each directory */
                q = rm_rf_children(subdir_fd, flags | REMOVE_PHYSICAL, root_dev);

        } else if (flags & REMOVE_ONLY_DIRECTORIES)
                return 0;

        r = unlinkat_harder(fd, fname, is_dir ? AT_REMOVEDIR : 0, flags);
        if (r < 0)
                return r;
        if (q < 0)
                return q;
        return 1;
}

typedef struct TodoEntry {
        DIR *dir;         /* A directory that we were operating on. */
        char *dirname;    /* The filename of that directory itself. */
} TodoEntry;

static void free_todo_entries(TodoEntry **todos) {
        for (TodoEntry *x = *todos; x && x->dir; x++) {
                closedir(x->dir);
                free(x->dirname);
        }

        freep(todos);
}

int rm_rf_children(
                int fd,
                RemoveFlags flags,
                const struct stat *root_dev) {

        _cleanup_(free_todo_entries) TodoEntry *todos = NULL;
        size_t n_todo = 0;
        _cleanup_free_ char *dirname = NULL; /* Set when we are recursing and want to delete ourselves */
        int ret = 0, r;

        /* Return the first error we run into, but nevertheless try to go on.
         * The passed fd is closed in all cases, including on failure. */

        for (;;) {  /* This loop corresponds to the directory nesting level. */
                _cleanup_closedir_ DIR *d = NULL;

                if (n_todo > 0) {
                        /* We know that we are in recursion here, because n_todo is set.
                         * We need to remove the inner directory we were operating on. */
                        assert(dirname);
                        r = unlinkat_harder(dirfd(todos[n_todo-1].dir), dirname, AT_REMOVEDIR, flags);
                        if (r < 0 && r != -ENOENT && ret == 0)
                                ret = r;
                        dirname = mfree(dirname);

                        /* And now let's back out one level up */
                        n_todo --;
                        d = TAKE_PTR(todos[n_todo].dir);
                        dirname = TAKE_PTR(todos[n_todo].dirname);

                        assert(d);
                        fd = dirfd(d); /* Retrieve the file descriptor from the DIR object */
                        assert(fd >= 0);
                } else {
        next_fd:
                        assert(fd >= 0);
                        d = fdopendir(fd);
                        if (!d) {
                                safe_close(fd);
                                return -errno;
                        }
                        fd = dirfd(d); /* We donated the fd to fdopendir(). Let's make sure we sure we have
                                        * the right descriptor even if it were to internally invalidate the
                                        * one we passed. */

                        if (!(flags & REMOVE_PHYSICAL)) {
                                struct statfs sfs;

                                if (fstatfs(fd, &sfs) < 0)
                                        return -errno;

                                if (is_physical_fs(&sfs)) {
                                        /* We refuse to clean physical file systems with this call, unless
                                         * explicitly requested. This is extra paranoia just to be sure we
                                         * never ever remove non-state data. */

                                        _cleanup_free_ char *path = NULL;

                                        (void) fd_get_path(fd, &path);
                                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                               "Attempted to remove disk file system under \"%s\", and we can't allow that.",
                                                               strna(path));
                                }
                        }
                }

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        int is_dir;

                        if (dot_or_dot_dot(de->d_name))
                                continue;

                        is_dir = de->d_type == DT_UNKNOWN ? -1 : de->d_type == DT_DIR;

                        r = rm_rf_inner_child(fd, de->d_name, is_dir, flags, root_dev, false);
                        if (r == -EISDIR) {
                                /* Push the current working state onto the todo list */

                                 if (!GREEDY_REALLOC0(todos, n_todo + 2))
                                         return log_oom();

                                 _cleanup_free_ char *newdirname = strdup(de->d_name);
                                 if (!newdirname)
                                         return log_oom();

                                 int newfd = openat(fd, de->d_name,
                                                    O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                                 if (newfd >= 0) {
                                         todos[n_todo++] = (TodoEntry) { TAKE_PTR(d), TAKE_PTR(dirname) };
                                         fd = newfd;
                                         dirname = TAKE_PTR(newdirname);

                                         goto next_fd;

                                 } else if (errno != -ENOENT && ret == 0)
                                         ret = -errno;

                        } else if (r < 0 && r != -ENOENT && ret == 0)
                                ret = r;
                }

                if (FLAGS_SET(flags, REMOVE_SYNCFS) && syncfs(fd) < 0 && ret >= 0)
                        ret = -errno;

                if (n_todo == 0)
                        break;
        }

        return ret;
}

int rm_rf(const char *path, RemoveFlags flags) {
        int fd, r, q = 0;

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
        if (fd >= 0) {
                /* We have a dir */
                r = rm_rf_children(fd, flags, NULL);

                if (FLAGS_SET(flags, REMOVE_ROOT))
                        q = RET_NERRNO(rmdir(path));
        } else {
                if (FLAGS_SET(flags, REMOVE_MISSING_OK) && errno == ENOENT)
                        return 0;

                if (!IN_SET(errno, ENOTDIR, ELOOP))
                        return -errno;

                if (FLAGS_SET(flags, REMOVE_ONLY_DIRECTORIES) || !FLAGS_SET(flags, REMOVE_ROOT))
                        return 0;

                if (!FLAGS_SET(flags, REMOVE_PHYSICAL)) {
                        struct statfs s;

                        if (statfs(path, &s) < 0)
                                return -errno;
                        if (is_physical_fs(&s))
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "Attempted to remove files from a disk file system under \"%s\", refusing.",
                                                       path);
                }

                r = 0;
                q = RET_NERRNO(unlink(path));
        }

        if (r < 0)
                return r;
        if (q < 0 && (q != -ENOENT || !FLAGS_SET(flags, REMOVE_MISSING_OK)))
                return q;
        return 0;
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

        return rm_rf_inner_child(fd, name, -1, flags, NULL, true);
}
