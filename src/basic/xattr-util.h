/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "time-util.h"

int getxattr_at_malloc(int fd, const char *path, const char *name, int at_flags, char **ret);
static inline int getxattr_malloc(const char *path, const char *name, char **ret) {
        return getxattr_at_malloc(AT_FDCWD, path, name, AT_SYMLINK_FOLLOW, ret);
}
static inline int lgetxattr_malloc(const char *path, const char *name, char **ret) {
        return getxattr_at_malloc(AT_FDCWD, path, name, 0, ret);
}
static inline int fgetxattr_malloc(int fd, const char *name, char **ret) {
        return getxattr_at_malloc(fd, NULL, name, AT_EMPTY_PATH, ret);
}

int getxattr_at_bool(int fd, const char *path, const char *name, int at_flags);

int listxattr_at_malloc(int fd, const char *path, int at_flags, char **ret);
static inline int listxattr_malloc(const char *path, char **ret) {
        return listxattr_at_malloc(AT_FDCWD, path, AT_SYMLINK_FOLLOW, ret);
}
static inline int llistxattr_malloc(const char *path, char **ret) {
        return listxattr_at_malloc(AT_FDCWD, path, 0, ret);
}
static inline int flistxattr_malloc(int fd, char **ret) {
        return listxattr_at_malloc(fd, NULL, AT_EMPTY_PATH, ret);
}

int xsetxattr_full(
                int fd,
                const char *path,
                int at_flags,
                const char *name,
                const char *value,
                size_t size,
                int xattr_flags);
static inline int xsetxattr(
                int fd,
                const char *path,
                int at_flags,
                const char *name,
                const char *value) {
        return xsetxattr_full(fd, path, at_flags, name, value, SIZE_MAX, 0);
}

int xremovexattr(int fd, const char *path, int at_flags, const char *name);

int fd_setcrtime(int fd, usec_t usec);
int getcrtime_at(int fd, const char *path, int at_flags, usec_t *ret);
static inline int fd_getcrtime(int fd, usec_t *ret) {
        return getcrtime_at(fd, NULL, 0, ret);
}
