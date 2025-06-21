/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/quota.h>        /* IWYU pragma: export */

#include_next <sys/quota.h>

#if !HAVE_QUOTACTL_FD
int quotactl_fd(int fd, int cmd, int id, void *addr);
#endif
