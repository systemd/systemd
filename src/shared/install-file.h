/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int fs_make_very_read_only(int fd);

typedef enum InstallFileFlags {
        INSTALL_REPLACE    = 1 << 0, /* Replace an existing inode */
        INSTALL_READ_ONLY  = 1 << 1, /* Call fs_make_very_read_only() to make the inode comprehensively read-only */
        INSTALL_FSYNC      = 1 << 2, /* fsync() file contents before moving file in */
        INSTALL_FSYNC_FULL = 1 << 3, /* like INSTALL_FSYNC, but also fsync() parent dir before+after moving file in */
        INSTALL_SYNCFS     = 1 << 4, /* syncfs() before moving file in, fsync() parent dir after moving file in */
} InstallFileFlags;

int install_file(int source_atfd, const char *source_name, int target_atfd, const char *target_name, InstallFileFlags flags);
