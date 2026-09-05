/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(close_range, int,
                    unsigned, first_fd,
                    unsigned, end_fd,
                    unsigned, flags)

DEFINE_SYSCALL_SHIM(pivot_root, int,
                    const char *, new_root,
                    const char *, put_old)
