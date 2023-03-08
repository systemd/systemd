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

int lockf_unposix(int fd, int cmd, off_t len);

int lockfp(int fd, int *fd_lock);
void unlockfp(int *fd_lock);
