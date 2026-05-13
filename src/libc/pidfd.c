/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/pidfd.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(pidfd_open, int,
                    pid_t, pid,
                    unsigned, flags)

DEFINE_SYSCALL_SHIM(pidfd_send_signal, int,
                    int, fd,
                    int, sig,
                    siginfo_t *, info,
                    unsigned, flags)
