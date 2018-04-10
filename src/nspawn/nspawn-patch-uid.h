/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#pragma once

#include <sys/types.h>

int fd_patch_uid(int fd, uid_t shift, uid_t range);
int path_patch_uid(const char *path, uid_t shift, uid_t range);
