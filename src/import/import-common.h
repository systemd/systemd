/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

typedef enum ImportFlags {
        IMPORT_FORCE     = 1 << 0, /* replace existing image */
        IMPORT_READ_ONLY = 1 << 1, /* make generated image read-only */

        IMPORT_FLAGS_MASK = IMPORT_FORCE|IMPORT_READ_ONLY,
} ImportFlags;

int import_make_read_only_fd(int fd);
int import_make_read_only(const char *path);

int import_fork_tar_c(const char *path, pid_t *ret);
int import_fork_tar_x(const char *path, pid_t *ret);

int import_mangle_os_tree(const char *path);
