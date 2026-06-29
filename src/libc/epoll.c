/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(
                epoll_pwait2,
                int,
                int, epfd,
                struct epoll_event *, events,
                int, maxevents,
                const struct __kernel_timespec *, timeout,
                const sigset_t *, sigmask,
                size_t, sigsetsize);
