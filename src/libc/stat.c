/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(fchmodat2, int,
                    int, dirfd,
                    const char *, path,
                    mode_t, mode,
                    int, flags)
