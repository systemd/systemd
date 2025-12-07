/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <unistd.h>        /* IWYU pragma: export */

/* Defined since glibc-2.34.
 * Supported since kernel v5.9 (9b4feb630e8e9801603f3cab3a36369e3c1cf88d). */
#if !HAVE_CLOSE_RANGE
int missing_close_range(unsigned first_fd, unsigned end_fd, unsigned flags);
#  define close_range(first_fd, end_fd, flags)          \
        missing_close_range(first_fd, end_fd, flags)
#endif

/* Defined since glibc-2.34.
 * Supported since kernel v3.19 (51f39a1f0cea1cacf8c787f652f26dfee9611874). */
#if !HAVE_EXECVEAT
int missing_execveat(int dirfd, const char *pathname, char * const argv[], char * const envp[], int flags);
#  define execveat(dirfd, pathname, argv, envp, flags)          \
        missing_execveat(dirfd, pathname, argv, envp, flags)
#endif

#if !HAVE_PIVOT_ROOT
int missing_pivot_root(const char *new_root, const char *put_old);
#  define pivot_root(new_root, put_old)         \
        missing_pivot_root(new_root, put_old)
#endif
