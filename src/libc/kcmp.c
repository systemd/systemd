/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/kcmp.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(kcmp, int,
                    pid_t, pid1,
                    pid_t, pid2,
                    int, type,
                    unsigned long, idx1,
                    unsigned long, idx2)
