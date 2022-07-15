/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

/* These functions are split out of tmpfile-util.h (and not for example just flags to the functions they
 * wrap) in order to optimize linking: this way, -lselinux is needed only for the callers of these functions
 * that need selinux, but not for all. */

int fopen_temporary_label(const char *target, const char *path, FILE **f, char **temp_path);
