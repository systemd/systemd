/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

typedef enum MakeFilesystemFlags {
        MKFS_QUIET     = 1 << 0,  /* Suppress mkfs command output */
        MKFS_DISCARD   = 1 << 1,  /* Enable 'discard' mode on the filesystem */
        MKFS_FS_VERITY = 1 << 2,  /* Enable fs-verity support on the filesystem */
} MakeFileSystemFlags;

int mkfs_exists(const char *fstype);

int mkfs_supports_root_option(const char *fstype);

int make_filesystem(
                const char *node,
                const char *fstype,
                const char *label,
                const char *root,
                sd_id128_t uuid,
                MakeFileSystemFlags flags,
                uint64_t sector_size,
                char *compression,
                char *compression_level,
                char * const *extra_mkfs_args);

int mkfs_options_from_env(const char *component, const char *fstype, char ***ret);
