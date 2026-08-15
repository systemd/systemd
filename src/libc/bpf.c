/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/bpf.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(bpf, int,
                    int, cmd,
                    union bpf_attr *, attr,
                    size_t, size)
