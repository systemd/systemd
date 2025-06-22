/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* glibc's sys/quota.h includes linux/quota.h since glibc-2.25 (4d728087ef8cc826b05bd21d0c74d4eca9b1a27d),
 * but musl's one does not. Let's explicitly include it here. */
#include <linux/quota.h>

#include_next <sys/quota.h>

#if !HAVE_QUOTACTL_FD
int quotactl_fd(int fd, int cmd, int id, void *addr);
#endif
