/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <glob.h>
#include <stdbool.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"

/* Note: this function modifies pglob to set various functions. */
int safe_glob(const char *path, int flags, glob_t *pglob);

int glob_exists(const char *path);
int glob_extend(char ***strv, const char *path);

#define _cleanup_globfree_ _cleanup_(globfree)

_pure_ static inline bool string_is_glob(const char *p) {
        /* Check if a string contains any glob patterns. */
        return !!strpbrk(p, GLOB_CHARS);
}
