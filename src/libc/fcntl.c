/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(openat2, int,
                    int, dfd,
                    const char *, filename,
                    const struct open_how *, how,
                    size_t, usize)
