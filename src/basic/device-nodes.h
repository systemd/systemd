/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stddef.h>
#include <sys/types.h>

#include "macro.h"
#include "stdio-util.h"

int encode_devnode_name(const char *str, char *str_enc, size_t len);
int whitelisted_char_for_devnode(char c, const char *additional);

#define DEV_NUM_PATH_MAX                                                \
        (STRLEN("/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t))
#define xsprintf_dev_num_path(buf, type, devno)                         \
        xsprintf(buf, "/dev/%s/%u:%u", type, major(devno), minor(devno))
