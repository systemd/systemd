/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

#if !HAVE_FCHMODAT2
int fchmodat2(int dirfd, const char *path, mode_t mode, int flags);
#endif

/* musl's sys/stat.h does not include linux/stat.h, hence some new macros may not be defined. */
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
