/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efivars-fundamental.h>
#include <uchar.h>

typedef enum SysFailType {
        SYSFAIL_OK = 0x0,
        _SYSFAIL_MAX,
        _SYSFAIL_INVALID = -EINVAL,
} SysFailType;

SysFailType sysfail_check(void);
const char16_t* sysfail_get_error_str(SysFailType fail_type);
