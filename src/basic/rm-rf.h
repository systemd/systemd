/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/stat.h>

#include "util.h"

typedef enum RemoveFlags {
        REMOVE_ONLY_DIRECTORIES = 1 << 0,
        REMOVE_ROOT             = 1 << 1,
        REMOVE_PHYSICAL         = 1 << 2, /* if not set, only removes files on tmpfs, never physical file systems */
        REMOVE_SUBVOLUME        = 1 << 3,
} RemoveFlags;

int rm_rf_children(int fd, RemoveFlags flags, struct stat *root_dev);
int rm_rf(const char *path, RemoveFlags flags);

/* Useful for usage with _cleanup_(), destroys a directory and frees the pointer */
static inline void rm_rf_physical_and_free(char *p) {
        PROTECT_ERRNO;
        (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rm_rf_physical_and_free);
