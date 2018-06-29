/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdio.h>

#include "fileio.h"

/* These functions are split out of fileio.h (and not for examplement just as flags to the functions they wrap) in
 * order to optimize linking: This way, -lselinux is needed only for the callers of these functions that need selinux,
 * but not for all */

int write_string_file_atomic_label_ts(const char *fn, const char *line, struct timespec *ts);
static inline int write_string_file_atomic_label(const char *fn, const char *line) {
        return write_string_file_atomic_label_ts(fn, line, NULL);
}
int write_env_file_label(const char *fname, char **l);
int fopen_temporary_label(const char *target, const char *path, FILE **f, char **temp_path);

int create_shutdown_run_nologin_or_warn(void);
