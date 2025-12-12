/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

typedef enum SysFailType {
        SYSFAIL_NO_FAILURE,
        SYSFAIL_FIRMWARE_UPDATE,
        _SYSFAIL_MAX,
} SysFailType;

SysFailType sysfail_check(void);
const char16_t* sysfail_get_error_str(SysFailType fail_type);
