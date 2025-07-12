/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

/* Supported since kernel v6.6 (78252deb023cf0879256fcfbafe37022c390762b). */
#if !HAVE_FCHMODAT2
int missing_fchmodat2(int dirfd, const char *path, mode_t mode, int flags);
#  define fchmodat2 missing_fchmodat2
#endif

/* musl's sys/stat.h does not include linux/stat.h, and unfortunately they conflict with each other.
 * Hence, some relatively new macros need to be explicitly defined here. */
#ifndef STATX_SUBVOL
#define STATX_SUBVOL            0x00008000U
#endif
#ifndef STATX_WRITE_ATOMIC
#define STATX_WRITE_ATOMIC      0x00010000U
#endif
#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN    0x00020000U
#endif

#ifndef STATX_ATTR_WRITE_ATOMIC
#define STATX_ATTR_WRITE_ATOMIC 0x00400000
#endif
