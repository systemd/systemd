/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <unistd.h>

int missing_close_range(unsigned first_fd, unsigned end_fd, unsigned flags);
#define close_range missing_close_range

int missing_execveat(int dirfd, const char *pathname, char * const argv[], char * const envp[], int flags);
#define execveat missing_execveat
