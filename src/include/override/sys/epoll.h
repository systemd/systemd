/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/epoll.h>     /* IWYU pragma: export */

/* epoll_pwait2() was added to glibc 2.35. Redirect to a shim that sets errno=ENOSYS at runtime when
 * the libc symbol isn't available, so callers don't need to worry about the libc version. */
int epoll_pwait2_shim(int fd, struct epoll_event *events, int maxevents,
                      const struct timespec *timeout, const sigset_t *sigmask);
#define epoll_pwait2 epoll_pwait2_shim
