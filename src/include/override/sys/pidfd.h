/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Here, we do not use glibc's pidfd.h, as its definition of struct pidfd_info is slightly older. */
#include <linux/pidfd.h>
#include <signal.h>

/* Defined since glibc-2.36.
 * Supported since kernel v5.3 (7615d9e1780e26e0178c93c55b73309a5dc093d7). */
#if HAVE_PIDFD_OPEN
extern int pidfd_open(__pid_t __pid, unsigned __flags);
#else
int missing_pidfd_open(pid_t pid, unsigned flags);
#  define pidfd_open missing_pidfd_open
#endif

/* Defined since glibc-2.36.
 * Supported since kernel v5.1 (3eb39f47934f9d5a3027fe00d906a45fe3a15fad). */
#if HAVE_PIDFD_SEND_SIGNAL
extern int pidfd_send_signal(int __pidfd, int __sig, siginfo_t *__info, unsigned __flags);
#else
int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags);
#  define pidfd_send_signal missing_pidfd_send_signal
#endif
