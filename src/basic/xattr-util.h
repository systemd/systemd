/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "time-util.h"

int getxattr_at_malloc(int fd, const char *path, const char *name, int flags, char **ret);
static inline int getxattr_malloc(const char *path, const char *name, char **ret) {
        return getxattr_at_malloc(AT_FDCWD, path, name, AT_SYMLINK_FOLLOW, ret);
}
static inline int lgetxattr_malloc(const char *path, const char *name, char **ret) {
        return getxattr_at_malloc(AT_FDCWD, path, name, 0, ret);
}
static inline int fgetxattr_malloc(int fd, const char *name, char **ret) {
        return getxattr_at_malloc(fd, NULL, name, AT_EMPTY_PATH, ret);
}

int getxattr_at_bool(int fd, const char *path, const char *name, int flags);

int fd_setcrtime(int fd, usec_t usec);

int fd_getcrtime_at(int fd, const char *name, int flags, usec_t *ret);
static inline int fd_getcrtime(int fd, usec_t *ret) {
        return fd_getcrtime_at(fd, NULL, 0, ret);
}

int listxattr_at_malloc(int fd, const char *path, int flags, char **ret);
static inline int listxattr_malloc(const char *path, char **ret) {
        return listxattr_at_malloc(AT_FDCWD, path, AT_SYMLINK_FOLLOW, ret);
}
static inline int llistxattr_malloc(const char *path, char **ret) {
        return listxattr_at_malloc(AT_FDCWD, path, 0, ret);
}
static inline int flistxattr_malloc(int fd, char **ret) {
        return listxattr_at_malloc(fd, NULL, AT_EMPTY_PATH, ret);
}

int xsetxattr(int fd, const char *path, const char *name, const char *value, size_t size, int flags);
