/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum TarFlags {
        TAR_SELINUX = 1 << 0,
} TarFlags;

int tar_x(int input_fd, int tree_fd, TarFlags flags);
int tar_c(int tree_fd, int output_fd, const char *filename, TarFlags flags);
