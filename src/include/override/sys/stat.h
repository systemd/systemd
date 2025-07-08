/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

/* Supported since kernel v6.6 (78252deb023cf0879256fcfbafe37022c390762b). */
#if !HAVE_FCHMODAT2
int missing_fchmodat2(int dirfd, const char *path, mode_t mode, int flags);
#  define fchmodat2 missing_fchmodat2
#endif
