/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(rt_tgsigqueueinfo, int,
                    pid_t, tgid,
                    pid_t, tid,
                    int, sig,
                    siginfo_t *, info)
