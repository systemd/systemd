/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2014 Kay Sievers
***/

#include <sys/types.h>

int base_filesystem_create(const char *root, uid_t uid, gid_t gid);
