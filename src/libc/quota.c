/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(quotactl_fd, int,
                    int, fd,
                    int, cmd,
                    int, id,
                    void *, addr)
