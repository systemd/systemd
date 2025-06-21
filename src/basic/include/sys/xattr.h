/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/xattr.h>

#include_next <sys/xattr.h>

#if !HAVE_SETXATTRAT
int setxattrat(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size);
#endif

#if !HAVE_REMOVEXATTRAT
int removexattrat(int fd, const char *path, int at_flags, const char *name);
#endif
