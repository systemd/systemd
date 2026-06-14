/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "../basic/tmpfile-util.h"   /* IWYU pragma: export */

/* These functions extend the basic tmpfile-util.h API with shared-only functionality (selinux labelling).
 * Targets that link libshared automatically pick up this version via -Isrc/shared; targets that only have
 * src/basic on their include path fall through to the basic header. */

int fopen_temporary_at_label(int dir_fd, const char *target, const char *path, FILE **f, char **temp_path);
static inline int fopen_temporary_label(const char *target, const char *path, FILE **f, char **temp_path) {
        return fopen_temporary_at_label(AT_FDCWD, target, path, f, temp_path);
}
