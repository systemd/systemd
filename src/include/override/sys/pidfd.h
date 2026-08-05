/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Here, we do not use glibc's pidfd.h, as its definition of struct pidfd_info may be slightly older. */
#include <linux/pidfd.h>
#include <signal.h>

/* Defined since glibc-2.36.
 * Supported since kernel v5.3 (7615d9e1780e26e0178c93c55b73309a5dc093d7). */
int pidfd_open_shim(pid_t pid, unsigned flags);
#define pidfd_open pidfd_open_shim

/* Defined since glibc-2.36.
 * Supported since kernel v5.1 (3eb39f47934f9d5a3027fe00d906a45fe3a15fad). */
int pidfd_send_signal_shim(int fd, int sig, siginfo_t *info, unsigned flags);
#define pidfd_send_signal pidfd_send_signal_shim
