/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/xattr.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(setxattrat, int,
                    int, fd,
                    const char *, path,
                    int, at_flags,
                    const char *, name,
                    const struct xattr_args *, args,
                    size_t, size)

DEFINE_SYSCALL_SHIM(removexattrat, int,
                    int, fd,
                    const char *, path,
                    int, at_flags,
                    const char *, name)
