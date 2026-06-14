/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioprio.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(ioprio_get, int,
                    int, which,
                    int, who)

DEFINE_SYSCALL_SHIM(ioprio_set, int,
                    int, which,
                    int, who,
                    int, ioprio)
