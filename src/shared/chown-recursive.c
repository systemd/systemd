/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "chown-recursive.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "path-util.h"
#include "strv.h"
#include "user-util.h"
#include "xattr-util.h"

static int chown_one(
                int fd,
                const struct stat *st,
                uid_t uid,
                gid_t gid,
                mode_t mask) {

        int r;

        assert(fd >= 0);
        assert(st);

        /* Drop any ACL if there is one */
        FOREACH_STRING(n, "system.posix_acl_access", "system.posix_acl_default") {
                r = xremovexattr(fd, /* path = */ NULL, AT_EMPTY_PATH, n);
                if (r < 0 && !ERRNO_IS_NEG_XATTR_ABSENT(r))
                        return r;
        }

        r = fchmod_and_chown(fd, st->st_mode & mask, uid, gid);
        if (r < 0)
                return r;

        return 1;
}

static int chown_recursive_internal(
                int fd,
                const struct stat *st,
                uid_t uid,
                gid_t gid,
                mode_t mask) {

        _cleanup_closedir_ DIR *d = NULL;
        bool changed = false;
        int r;

        assert(fd >= 0);
        assert(st);

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                _cleanup_close_ int path_fd = -EBADF;
                struct stat fst;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                /* Let's pin the child inode we want to fix now with an O_PATH fd, so that it cannot be swapped out
                 * while we manipulate it. */
                path_fd = openat(dirfd(d), de->d_name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (path_fd < 0)
                        return -errno;

                if (fstat(path_fd, &fst) < 0)
                        return -errno;

                if (S_ISDIR(fst.st_mode)) {
                        int subdir_fd;

                        /* Convert it to a "real" (i.e. non-O_PATH) fd now */
                        subdir_fd = fd_reopen(path_fd, O_RDONLY|O_CLOEXEC|O_NOATIME);
                        if (subdir_fd < 0)
                                return subdir_fd;

                        r = chown_recursive_internal(subdir_fd, &fst, uid, gid, mask); /* takes possession of subdir_fd even on failure */
                        if (r < 0)
                                return r;
                        if (r > 0)
                                changed = true;
                } else {
                        r = chown_one(path_fd, &fst, uid, gid, mask);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                changed = true;
                }
        }

        r = chown_one(dirfd(d), st, uid, gid, mask);
        if (r < 0)
                return r;

        return r > 0 || changed;
}

int path_chown_recursive(
                const char *path,
                uid_t uid,
                gid_t gid,
                mode_t mask,
                int flags) {

        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        fd = open(path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOATIME|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
        if (fd < 0)
                return -errno;

        if (!uid_is_valid(uid) && !gid_is_valid(gid) && FLAGS_SET(mask, 07777))
                return 0; /* nothing to do */

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Let's take a shortcut: if the top-level directory is properly owned, we don't descend into the
         * whole tree, under the assumption that all is OK anyway. */
        if ((!uid_is_valid(uid) || st.st_uid == uid) &&
            (!gid_is_valid(gid) || st.st_gid == gid) &&
            ((st.st_mode & ~mask & 07777) == 0))
                return 0;

        return chown_recursive_internal(TAKE_FD(fd), &st, uid, gid, mask); /* we donate the fd to the call, regardless if it succeeded or failed */
}

int fd_chown_recursive(
                int fd,
                uid_t uid,
                gid_t gid,
                mode_t mask) {

        int duplicated_fd = -EBADF;
        struct stat st;

        /* Note that the slightly different order of fstat() and the checks here and in
         * path_chown_recursive(). That's because when we open the directory ourselves we can specify
         * O_DIRECTORY and we always want to ensure we are operating on a directory before deciding whether
         * the operation is otherwise redundant. */

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;

        if (!uid_is_valid(uid) && !gid_is_valid(gid) && FLAGS_SET(mask, 07777))
                return 0; /* nothing to do */

        /* Shortcut, as above */
        if ((!uid_is_valid(uid) || st.st_uid == uid) &&
            (!gid_is_valid(gid) || st.st_gid == gid) &&
            ((st.st_mode & ~mask & 07777) == 0))
                return 0;

        /* Let's duplicate the fd here, as opendir() wants to take possession of it and close it afterwards */
        duplicated_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (duplicated_fd < 0)
                return -errno;

        return chown_recursive_internal(duplicated_fd, &st, uid, gid, mask); /* fd donated even on failure */
}
