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

bool mac_smack_use(void);

int mac_smack_fix(const char *path, bool ignore_enoent, bool ignore_erofs);

int mac_smack_apply(const char *path, const char *label);
int mac_smack_apply_fd(int fd, const char *label);
int mac_smack_apply_pid(pid_t pid, const char *label);
int mac_smack_apply_ip_in_fd(int fd, const char *label);
int mac_smack_apply_ip_out_fd(int fd, const char *label);
