/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* To make struct xattr_args defined, which is used by setxattrat(). Note, the kernel header must be
 * included before the glibc header, otherwise the struct will not be defined. */
#include <linux/xattr.h>

#include_next <sys/xattr.h>

#if !HAVE_SETXATTRAT
int setxattrat(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size);
#endif

#if !HAVE_REMOVEXATTRAT
int removexattrat(int fd, const char *path, int at_flags, const char *name);
#endif
