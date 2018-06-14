/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/types.h>

#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

#define SYS_BLOCK_PATH_MAX(suffix)                                      \
        (STRLEN("/sys/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t) + strlen_ptr(suffix))
#define xsprintf_sys_block_path(buf, suffix, devno)                     \
        xsprintf(buf, "/sys/dev/block/%u:%u%s", major(devno), minor(devno), strempty(suffix))

int block_get_whole_disk(dev_t d, dev_t *ret);
int block_get_originating(dev_t d, dev_t *ret);

int get_block_device(const char *path, dev_t *dev);

int get_block_device_harder(const char *path, dev_t *dev);
