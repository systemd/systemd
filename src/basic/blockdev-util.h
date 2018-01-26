/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/types.h>

#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

#define SYS_BLOCK_PATH_MAX(suffix)                                      \
        (STRLEN("/sys/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t) + strlen_ptr(suffix))
#define xsprintf_sys_block_path(buf, suffix, devno)                     \
        xsprintf(buf, "/sys/dev/block/%u:%u%s", major(devno), minor(devno), strempty(suffix))

int block_get_whole_disk(dev_t d, dev_t *ret);

int get_block_device(const char *path, dev_t *dev);

int get_block_device_harder(const char *path, dev_t *dev);
