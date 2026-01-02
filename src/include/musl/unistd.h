/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* getopt() is provided both in getopt.h and unistd.h. Hence, we need to tentatively undefine it. */
#undef getopt

#include_next <unistd.h>

/* musl's getopt() always behaves POSIXLY_CORRECT mode, and stops parsing arguments when a non-option string
 * found. Let's always use getopt_long(). */
int getopt_fix(int argc, char * const *argv, const char *optstring);
#define getopt(argc, argv, optstring) getopt_fix(argc, argv, optstring)

int missing_close_range(unsigned first_fd, unsigned end_fd, unsigned flags);
#define close_range missing_close_range

int missing_execveat(int dirfd, const char *pathname, char * const argv[], char * const envp[], int flags);
#define execveat missing_execveat
