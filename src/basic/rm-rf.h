/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/stat.h>

#include "errno-util.h"

typedef enum RemoveFlags {
        REMOVE_ONLY_DIRECTORIES = 1 << 0, /* Only remove empty directories, no files */
        REMOVE_ROOT             = 1 << 1, /* Remove the specified directory itself too, not just the contents of it */
        REMOVE_PHYSICAL         = 1 << 2, /* If not set, only removes files on tmpfs, never physical file systems */
        REMOVE_SUBVOLUME        = 1 << 3, /* Drop btrfs subvolumes in the tree too */
        REMOVE_MISSING_OK       = 1 << 4, /* If the top-level directory is missing, ignore the ENOENT for it */
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

/* Similar as above, but also has magic btrfs subvolume powers */
static inline void rm_rf_subvolume_and_free(char *p) {
        PROTECT_ERRNO;
        (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rm_rf_subvolume_and_free);
