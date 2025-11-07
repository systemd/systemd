/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum TarFlags {
        TAR_SELINUX               = 1 << 0, /* Include SELinux xattr in tarball, or unpack it */
        TAR_SQUASH_UIDS_ABOVE_64K = 1 << 1, /* Squash UIDs/GIDs above 64K when packing/unpacking to the nobody user */
        TAR_OCI_WHITEOUTS         = 1 << 2, /* Turn OCI/aufs whiteout inodes into overlayfs whiteouts */
} TarFlags;

int tar_x(int input_fd, int tree_fd, TarFlags flags);
int tar_c(int tree_fd, int output_fd, const char *filename, TarFlags flags);
