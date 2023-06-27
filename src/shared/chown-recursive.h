/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int path_chown_recursive(const char *path, uid_t uid, gid_t gid, mode_t mask, int flags);

int fd_chown_recursive(int fd, uid_t uid, gid_t gid, mode_t mask);
