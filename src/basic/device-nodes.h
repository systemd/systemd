/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
