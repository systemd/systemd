/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/quota.h>     /* IWYU pragma: export */

/* Supported since kernel v5.14 (64c2c2c62f92339b176ea24403d8db16db36f9e6). */
int quotactl_fd_shim(int fd, int cmd, int id, void *addr);
#define quotactl_fd quotactl_fd_shim
