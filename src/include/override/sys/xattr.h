/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* To make struct xattr_args defined, which is used by setxattrat(). Note, the kernel header must be
 * included before the glibc header, otherwise the struct will not be defined. */
#include <linux/xattr.h>

#include_next <sys/xattr.h>

/* Supported since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394). */
#if !HAVE_SETXATTRAT
int missing_setxattrat(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size);
#  define setxattrat missing_setxattrat
#endif

/* Supported since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394). */
#if !HAVE_REMOVEXATTRAT
int missing_removexattrat(int fd, const char *path, int at_flags, const char *name);
#  define removexattrat missing_removexattrat
#endif
