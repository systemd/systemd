/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "user-util.h"
#include "macro.h"
#include "fd-util.h"
#include "dirent-util.h"
#include "chown-recursive.h"

static int chown_one(int fd, const char *name, const struct stat *st, uid_t uid, gid_t gid) {
        int r;

        assert(fd >= 0);
        assert(st);

        if ((!uid_is_valid(uid) || st->st_uid == uid) &&
            (!gid_is_valid(gid) || st->st_gid == gid))
                return 0;

        if (name)
                r = fchownat(fd, name, uid, gid, AT_SYMLINK_NOFOLLOW);
        else
                r = fchown(fd, uid, gid);
        if (r < 0)
                return -errno;

        /* The linux kernel alters the mode in some cases of chown(). Let's undo this. */
        if (name) {
                if (!S_ISLNK(st->st_mode))
                        r = fchmodat(fd, name, st->st_mode, 0);
                else /* There's currently no AT_SYMLINK_NOFOLLOW for fchmodat() */
                        r = 0;
        } else
                r = fchmod(fd, st->st_mode);
        if (r < 0)
                return -errno;

        return 1;
}

static int chown_recursive_internal(int fd, const struct stat *st, uid_t uid, gid_t gid) {
        bool changed = false;
        int r;

        assert(fd >= 0);
        assert(st);

        if (S_ISDIR(st->st_mode)) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = fdopendir(fd);
                if (!d) {
                        r = -errno;
                        goto finish;
                }
                fd = -1;

                FOREACH_DIRENT_ALL(de, d, r = -errno; goto finish) {
                        struct stat fst;

                        if (dot_or_dot_dot(de->d_name))
                                continue;

                        if (fstatat(dirfd(d), de->d_name, &fst, AT_SYMLINK_NOFOLLOW) < 0) {
                                r = -errno;
                                goto finish;
                        }

                        if (S_ISDIR(fst.st_mode)) {
                                int subdir_fd;

                                subdir_fd = openat(dirfd(d), de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                                if (subdir_fd < 0) {
                                        r = -errno;
                                        goto finish;
                                }

                                r = chown_recursive_internal(subdir_fd, &fst, uid, gid);
                                if (r < 0)
                                        goto finish;
                                if (r > 0)
                                        changed = true;
                        } else {
                                r = chown_one(dirfd(d), de->d_name, &fst, uid, gid);
                                if (r < 0)
                                        goto finish;
                                if (r > 0)
                                        changed = true;
                        }
                }

                r = chown_one(dirfd(d), NULL, st, uid, gid);
        } else
                r = chown_one(fd, NULL, st, uid, gid);
        if (r < 0)
                goto finish;

        r = r > 0 || changed;

finish:
        safe_close(fd);
        return r;
}

int path_chown_recursive(const char *path, uid_t uid, gid_t gid) {
        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0)
                return -errno;

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0; /* nothing to do */

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Let's take a shortcut: if the top-level directory is properly owned, we don't descend into the whole tree,
         * under the assumption that all is OK anyway. */

        if ((!uid_is_valid(uid) || st.st_uid == uid) &&
            (!gid_is_valid(gid) || st.st_gid == gid))
                return 0;

        r = chown_recursive_internal(fd, &st, uid, gid);
        fd = -1; /* we donated the fd to the call, regardless if it succeeded or failed */

        return r;
}
