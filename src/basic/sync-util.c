/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "fd-util.h"
#include "fs-util.h"
#include "path-util.h"
#include "sync-util.h"

int fsync_directory_of_file(int fd) {
        _cleanup_close_ int dfd = -1;
        struct stat st;
        int r;

        assert(fd >= 0);

        /* We only reasonably can do this for regular files and directories, or for O_PATH fds, hence check
         * for the inode type first */
        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISDIR(st.st_mode)) {
                dfd = openat(fd, "..", O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0);
                if (dfd < 0)
                        return -errno;

        } else if (!S_ISREG(st.st_mode)) { /* Regular files are OK regardless if O_PATH or not, for all other
                                            * types check O_PATH flag */
                int flags;

                flags = fcntl(fd, F_GETFL);
                if (flags < 0)
                        return -errno;

                if (!FLAGS_SET(flags, O_PATH)) /* If O_PATH this refers to the inode in the fs, in which case
                                                * we can sensibly do what is requested. Otherwise this refers
                                                * to a socket, fifo or device node, where the concept of a
                                                * containing directory doesn't make too much sense. */
                        return -ENOTTY;
        }

        if (dfd < 0) {
                _cleanup_free_ char *path = NULL;

                r = fd_get_path(fd, &path);
                if (r < 0) {
                        log_debug_errno(r, "Failed to query /proc/self/fd/%d%s: %m",
                                        fd,
                                        r == -ENOSYS ? ", ignoring" : "");

                        if (r == -ENOSYS)
                                /* If /proc is not available, we're most likely running in some
                                 * chroot environment, and syncing the directory is not very
                                 * important in that case. Let's just silently do nothing. */
                                return 0;

                        return r;
                }

                if (!path_is_absolute(path))
                        return -EINVAL;

                dfd = open_parent(path, O_CLOEXEC|O_NOFOLLOW, 0);
                if (dfd < 0)
                        return dfd;
        }

        return RET_NERRNO(fsync(dfd));
}

int fsync_full(int fd) {
        int r, q;

        /* Sync both the file and the directory */

        r = RET_NERRNO(fsync(fd));

        q = fsync_directory_of_file(fd);
        if (r < 0) /* Return earlier error */
                return r;
        if (q == -ENOTTY) /* Ignore if the 'fd' refers to a block device or so which doesn't really have a
                           * parent dir */
                return 0;
        return q;
}

int fsync_path_at(int at_fd, const char *path) {
        _cleanup_close_ int opened_fd = -1;
        int fd;

        if (isempty(path)) {
                if (at_fd == AT_FDCWD) {
                        opened_fd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                        if (opened_fd < 0)
                                return -errno;

                        fd = opened_fd;
                } else
                        fd = at_fd;
        } else {
                opened_fd = openat(at_fd, path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
        }

        return RET_NERRNO(fsync(fd));
}

int fsync_parent_at(int at_fd, const char *path) {
        _cleanup_close_ int opened_fd = -1;

        if (isempty(path)) {
                if (at_fd != AT_FDCWD)
                        return fsync_directory_of_file(at_fd);

                opened_fd = open("..", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (opened_fd < 0)
                        return -errno;

                return RET_NERRNO(fsync(opened_fd));
        }

        opened_fd = openat(at_fd, path, O_PATH|O_CLOEXEC|O_NOFOLLOW);
        if (opened_fd < 0)
                return -errno;

        return fsync_directory_of_file(opened_fd);
}

int fsync_path_and_parent_at(int at_fd, const char *path) {
        _cleanup_close_ int opened_fd = -1;

        if (isempty(path)) {
                if (at_fd != AT_FDCWD)
                        return fsync_full(at_fd);

                opened_fd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        } else
                opened_fd = openat(at_fd, path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (opened_fd < 0)
                return -errno;

        return fsync_full(opened_fd);
}

int syncfs_path(int at_fd, const char *path) {
        _cleanup_close_ int fd = -1;

        if (isempty(path)) {
                if (at_fd != AT_FDCWD)
                        return RET_NERRNO(syncfs(at_fd));

                fd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        } else
                fd = openat(at_fd, path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        return RET_NERRNO(syncfs(fd));
}
