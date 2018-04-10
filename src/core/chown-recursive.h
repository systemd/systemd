/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering
***/

#include <sys/types.h>

int path_chown_recursive(const char *path, uid_t uid, gid_t gid);
