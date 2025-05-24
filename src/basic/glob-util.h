/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glob.h>       /* IWYU pragma: export */

#include "forward.h"

/* Note: this function modifies pglob to set various functions. */
int safe_glob(const char *path, int flags, glob_t *pglob);

/* Note: which match is returned depends on the implementation/system and not guaranteed to be stable */
int glob_first(const char *path, char **ret_first);
#define glob_exists(path) glob_first(path, NULL)
int glob_extend(char ***strv, const char *path, int flags);

int glob_non_glob_prefix(const char *path, char **ret);

#define _cleanup_globfree_ _cleanup_(globfree)

bool string_is_glob(const char *p) _pure_;
