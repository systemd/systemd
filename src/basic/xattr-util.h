/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "time-util.h"

int getxattr_malloc(const char *path, const char *name, char **value, bool allow_symlink);
int fgetxattr_malloc(int fd, const char *name, char **value);

int fgetxattrat_fake(
                int dirfd,
                const char *filename,
                const char *attribute,
                void *value, size_t size,
                int flags,
                size_t *ret_size);

int fd_setcrtime(int fd, usec_t usec);

int fd_getcrtime(int fd, usec_t *usec);
int path_getcrtime(const char *p, usec_t *usec);
int fd_getcrtime_at(int dirfd, const char *name, usec_t *usec, int flags);
