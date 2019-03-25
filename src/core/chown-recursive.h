/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/types.h>

int path_chown_recursive(const char *path, uid_t uid, gid_t gid, mode_t mask);
