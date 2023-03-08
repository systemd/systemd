/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <fcntl.h>

typedef struct LockFile {
        char *path;
        int fd;
        int operation;
} LockFile;

int make_lock_file(const char *p, int operation, LockFile *ret);
int make_lock_file_for(const char *p, int operation, LockFile *ret);
void release_lock_file(LockFile *f);

#define LOCK_FILE_INIT { .fd = -EBADF, .path = NULL }

static inline int lockfp(int fd, int *fd_lock) {
        if (lockf(fd, F_LOCK, 0) < 0)
                return -errno;
        *fd_lock = fd;
        return 0;
}

static inline void unlockfp(int *fd_lock) {
        if (*fd_lock < 0)
                return;
        lockf(*fd_lock, F_ULOCK, 0);
        *fd_lock = -EBADF;
}
