/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct LockFile {
        char *path;
        int fd;
        int operation;
} LockFile;

int make_lock_file(const char *p, int operation, LockFile *ret);
int make_lock_file_for(const char *p, int operation, LockFile *ret);
void release_lock_file(LockFile *f);

#define LOCK_FILE_INIT { .fd = -EBADF, .path = NULL }

/* POSIX locks with the same interface as flock(). */
int posix_lock(int fd, int operation);
void posix_unlockpp(int **fd);

#define CLEANUP_POSIX_UNLOCK(fd)                                   \
        _cleanup_(posix_unlockpp) _unused_ int *CONCATENATE(_cleanup_posix_unlock_, UNIQ) = &(fd)

/* Open File Description locks with the same interface as flock(). */
int unposix_lock(int fd, int operation);
void unposix_unlockpp(int **fd);

#define CLEANUP_UNPOSIX_UNLOCK(fd)                                   \
        _cleanup_(unposix_unlockpp) _unused_ int *CONCATENATE(_cleanup_unposix_unlock_, UNIQ) = &(fd)
