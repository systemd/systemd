/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "lockfile-util.h"
#include "macro.h"
#include "path-util.h"

int make_lock_file(const char *p, int operation, LockFile *ret) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *t = NULL;
        int r;

        /*
         * We use UNPOSIX locks if they are available. They have nice
         * semantics, and are mostly compatible with NFS. However,
         * they are only available on new kernels. When we detect we
         * are running on an older kernel, then we fall back to good
         * old BSD locks. They also have nice semantics, but are
         * slightly problematic on NFS, where they are upgraded to
         * POSIX locks, even though locally they are orthogonal to
         * POSIX locks.
         */

        t = strdup(p);
        if (!t)
                return -ENOMEM;

        for (;;) {
                struct flock fl = {
                        .l_type = (operation & ~LOCK_NB) == LOCK_EX ? F_WRLCK : F_RDLCK,
                        .l_whence = SEEK_SET,
                };
                struct stat st;

                fd = open(p, O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY, 0600);
                if (fd < 0)
                        return -errno;

                r = fcntl(fd, (operation & LOCK_NB) ? F_OFD_SETLK : F_OFD_SETLKW, &fl);
                if (r < 0) {

                        /* If the kernel is too old, use good old BSD locks */
                        if (errno == EINVAL)
                                r = flock(fd, operation);

                        if (r < 0)
                                return errno == EAGAIN ? -EBUSY : -errno;
                }

                /* If we acquired the lock, let's check if the file
                 * still exists in the file system. If not, then the
                 * previous exclusive owner removed it and then closed
                 * it. In such a case our acquired lock is worthless,
                 * hence try again. */

                r = fstat(fd, &st);
                if (r < 0)
                        return -errno;
                if (st.st_nlink > 0)
                        break;

                fd = safe_close(fd);
        }

        ret->path = t;
        ret->fd = fd;
        ret->operation = operation;

        fd = -1;
        t = NULL;

        return r;
}

int make_lock_file_for(const char *p, int operation, LockFile *ret) {
        const char *fn;
        char *t;

        assert(p);
        assert(ret);

        fn = basename(p);
        if (!filename_is_valid(fn))
                return -EINVAL;

        t = newa(char, strlen(p) + 2 + 4 + 1);
        stpcpy(stpcpy(stpcpy(mempcpy(t, p, fn - p), ".#"), fn), ".lck");

        return make_lock_file(t, operation, ret);
}

void release_lock_file(LockFile *f) {
        int r;

        if (!f)
                return;

        if (f->path) {

                /* If we are the exclusive owner we can safely delete
                 * the lock file itself. If we are not the exclusive
                 * owner, we can try becoming it. */

                if (f->fd >= 0 &&
                    (f->operation & ~LOCK_NB) == LOCK_SH) {
                        static const struct flock fl = {
                                .l_type = F_WRLCK,
                                .l_whence = SEEK_SET,
                        };

                        r = fcntl(f->fd, F_OFD_SETLK, &fl);
                        if (r < 0 && errno == EINVAL)
                                r = flock(f->fd, LOCK_EX|LOCK_NB);

                        if (r >= 0)
                                f->operation = LOCK_EX|LOCK_NB;
                }

                if ((f->operation & ~LOCK_NB) == LOCK_EX)
                        unlink_noerrno(f->path);

                f->path = mfree(f->path);
        }

        f->fd = safe_close(f->fd);
        f->operation = 0;
}
