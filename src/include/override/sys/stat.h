/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>      /* IWYU pragma: export */

/* Supported since kernel v6.6 (78252deb023cf0879256fcfbafe37022c390762b). */
int fchmodat2_shim(int dirfd, const char *path, mode_t mode, int flags);
#define fchmodat2 fchmodat2_shim
