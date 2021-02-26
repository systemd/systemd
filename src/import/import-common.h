/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "sd-event.h"

typedef enum ImportFlags {
        IMPORT_FORCE          = 1 << 0, /* replace existing image */
        IMPORT_READ_ONLY      = 1 << 1, /* make generated image read-only */
        IMPORT_BTRFS_SUBVOL   = 1 << 2, /* tar: preferably create images as btrfs subvols */
        IMPORT_BTRFS_QUOTA    = 1 << 3, /* tar: set up btrfs quota for new subvolume as child of parent subvolume */
        IMPORT_CONVERT_QCOW2  = 1 << 4, /* raw: if we detect a qcow2 image, unpack it */
        IMPORT_DIRECT         = 1 << 5, /* import without rename games */
        IMPORT_SYNC           = 1 << 6, /* fsync() right before we are done */

        IMPORT_FLAGS_MASK_TAR = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_BTRFS_SUBVOL|IMPORT_BTRFS_QUOTA|IMPORT_DIRECT|IMPORT_SYNC,
        IMPORT_FLAGS_MASK_RAW = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_CONVERT_QCOW2|IMPORT_DIRECT|IMPORT_SYNC,
} ImportFlags;

int import_fork_tar_c(const char *path, pid_t *ret);
int import_fork_tar_x(const char *path, pid_t *ret);

int import_mangle_os_tree(const char *path);

bool import_validate_local(const char *name, ImportFlags flags);

int import_allocate_event_with_signals(sd_event **ret);
