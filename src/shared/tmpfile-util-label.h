/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* These functions are split out of tmpfile-util.h (and not for example just flags to the functions they
 * wrap) in order to optimize linking: this way, -lselinux is needed only for the callers of these functions
 * that need selinux, but not for all. */

int fopen_temporary_at_label(int dir_fd, const char *target, const char *path, FILE **f, char **temp_path);
static inline int fopen_temporary_label(const char *target, const char *path, FILE **f, char **temp_path) {
        return fopen_temporary_at_label(AT_FDCWD, target, path, f, temp_path);
}
