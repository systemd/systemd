/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efivars-fundamental.h"

typedef enum SysFailType {
        SYSFAIL_NO_FAILURE = 0x0,
        SYSFAIL_FIRMWARE_UPDATE,
        _SYSFAIL_MAX,
        _SYSFAIL_INVALID = -EINVAL,
} SysFailType;

typedef struct SysFailConfig {
        bool check_firmware_update;
} SysFailConfig;

SysFailType sysfail_check(SysFailConfig *sysfail_config);
const char16_t* sysfail_get_error_str(SysFailType fail_type);
