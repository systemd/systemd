/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int base_filesystem_create(const char *root, uid_t uid, gid_t gid);
