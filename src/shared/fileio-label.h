/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

/* These functions are split out of fileio.h (and not for example just flags to the functions they wrap) in order to
 * optimize linking: This way, -lselinux is needed only for the callers of these functions that need selinux, but not
 * for all */

#include "fileio.h"

int write_string_file_full_label(int atfd, const char *fn, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_file_at_label(int atfd, const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_full_label(atfd, fn, line, flags, /* ts= */ NULL);
}
static inline int write_string_file_atomic_label(const char *fn, const char *line) {
        return write_string_file_at_label(AT_FDCWD, fn, line, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
}

int create_shutdown_run_nologin_or_warn(void);
