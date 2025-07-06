/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/quota.h>

/* glibc's sys/quota.h includes linux/quota.h since glibc-2.25 (4d728087ef8cc826b05bd21d0c74d4eca9b1a27d),
 * but musl's one does not. Let's explicitly include it here. */
#include <linux/quota.h>

/* Supported since kernel v5.14 (64c2c2c62f92339b176ea24403d8db16db36f9e6). */
#if !HAVE_QUOTACTL_FD
int missing_quotactl_fd(int fd, int cmd, int id, void *addr);
#  define quotactl_fd missing_quotactl_fd
#endif
