/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>

#include "libc-shim.h"

DEFINE_LIBC_ERRNO_SHIM(epoll_pwait2, int,
                       int, fd,
                       struct epoll_event *, events,
                       int, maxevents,
                       const struct timespec *, timeout,
                       const sigset_t *, sigmask)
