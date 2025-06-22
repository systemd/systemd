/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* glibc's sys/quota.h includes linux/quota.h, but musl's one does not.
 * Let's explicitly include it here. */
#include <linux/quota.h>

#include_next <sys/quota.h>

#if !HAVE_QUOTACTL_FD
int quotactl_fd(int fd, int cmd, int id, void *addr);
#endif
