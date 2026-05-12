/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(sched_setattr, int,
                    pid_t, pid,
                    struct sched_attr *, attr,
                    unsigned, flags)
