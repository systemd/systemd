/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glob.h>       /* IWYU pragma: export */

#include "basic-forward.h"

typedef DIR* (*opendir_t)(const char *);

int safe_glob_full(const char *path, int flags, opendir_t opendir_func, char ***ret);
static inline int safe_glob(const char *path, int flags, char ***ret) {
        return safe_glob_full(path, flags, NULL, ret);
}

/* Note: which match is returned depends on the implementation/system and not guaranteed to be stable */
int glob_first(const char *path, char **ret);
#define glob_exists(path) glob_first(path, NULL)
int glob_extend(char ***strv, const char *path, int flags);

int glob_non_glob_prefix(const char *path, char **ret);

bool string_is_glob(const char *p) _pure_;
