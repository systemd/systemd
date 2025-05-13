/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum ImportFlags {
        /* Public Flags (i.e. accessible via D-Bus, must stay stable! */
        IMPORT_FORCE                   = 1 <<  0, /* replace existing image */
        IMPORT_READ_ONLY               = 1 <<  1, /* make generated image read-only */
        IMPORT_PULL_KEEP_DOWNLOAD      = 1 <<  2, /* keep a pristine copy of the downloaded file around */

        /* Private flags */
        IMPORT_BTRFS_SUBVOL            = 1 <<  3, /* tar: preferably create images as btrfs subvols */
        IMPORT_BTRFS_QUOTA             = 1 <<  4, /* tar: set up btrfs quota for new subvolume as child of parent subvolume */
        IMPORT_CONVERT_QCOW2           = 1 <<  5, /* raw: if we detect a qcow2 image, unpack it */
        IMPORT_DIRECT                  = 1 <<  6, /* import without rename games */
        IMPORT_SYNC                    = 1 <<  7, /* fsync() right before we are done */

        /* When pulling these flags are defined too */
        IMPORT_PULL_SETTINGS           = 1 <<  8, /* download .nspawn settings file */
        IMPORT_PULL_ROOTHASH           = 1 <<  9, /* only for raw: download .roothash file for verity */
        IMPORT_PULL_ROOTHASH_SIGNATURE = 1 << 10, /* only for raw: download .roothash.p7s file for verity */
        IMPORT_PULL_VERITY             = 1 << 11, /* only for raw: download .verity file for verity */

        /* The supported flags for the tar and the raw importing */
        IMPORT_FLAGS_MASK_TAR          = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_BTRFS_SUBVOL|IMPORT_BTRFS_QUOTA|IMPORT_DIRECT|IMPORT_SYNC,
        IMPORT_FLAGS_MASK_RAW          = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_CONVERT_QCOW2|IMPORT_DIRECT|IMPORT_SYNC,

        /* The supported flags for the tar and the raw pulling */
        IMPORT_PULL_FLAGS_MASK_TAR     = IMPORT_FLAGS_MASK_TAR|IMPORT_PULL_KEEP_DOWNLOAD|IMPORT_PULL_SETTINGS,
        IMPORT_PULL_FLAGS_MASK_RAW     = IMPORT_FLAGS_MASK_RAW|IMPORT_PULL_KEEP_DOWNLOAD|IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY,

        _IMPORT_FLAGS_INVALID = -EINVAL,
} ImportFlags;

int import_fork_tar_c(const char *path, pid_t *ret);
int import_fork_tar_x(const char *path, pid_t *ret);

int import_mangle_os_tree(const char *path);

bool import_validate_local(const char *name, ImportFlags flags);

int import_allocate_event_with_signals(sd_event **ret);
