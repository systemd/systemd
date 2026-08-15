/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mempolicy.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(set_mempolicy, int,
                    int, mode,
                    const unsigned long *, nodemask,
                    unsigned long, maxnode)

DEFINE_SYSCALL_SHIM(get_mempolicy, int,
                    int *, mode,
                    unsigned long *, nodemask,
                    unsigned long, maxnode,
                    void *, addr,
                    unsigned long, flags)
