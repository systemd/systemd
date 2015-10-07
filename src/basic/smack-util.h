/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "macro.h"

#define SMACK_FLOOR_LABEL "_"
#define SMACK_STAR_LABEL  "*"

typedef enum SmackAttr {
        SMACK_ATTR_ACCESS = 0,
        SMACK_ATTR_EXEC = 1,
        SMACK_ATTR_MMAP = 2,
        SMACK_ATTR_TRANSMUTE = 3,
        SMACK_ATTR_IPIN = 4,
        SMACK_ATTR_IPOUT = 5,
        _SMACK_ATTR_MAX,
        _SMACK_ATTR_INVALID = -1,
} SmackAttr;

bool mac_smack_use(void);

int mac_smack_fix(const char *path, bool ignore_enoent, bool ignore_erofs);

const char* smack_attr_to_string(SmackAttr i) _const_;
SmackAttr smack_attr_from_string(const char *s) _pure_;
int mac_smack_read(const char *path, SmackAttr attr, char **label);
int mac_smack_read_fd(int fd, SmackAttr attr, char **label);
int mac_smack_apply(const char *path, SmackAttr attr, const char *label);
int mac_smack_apply_fd(int fd, SmackAttr attr, const char *label);
int mac_smack_apply_pid(pid_t pid, const char *label);
int mac_smack_copy(const char *dest, const char *src);
