/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efivars-fundamental.h"

typedef enum SysFailType {
        SYSFAIL_NO_FAILURE,
        _SYSFAIL_MAX,
} SysFailType;

SysFailType sysfail_check(void);
const char16_t* sysfail_get_error_str(SysFailType fail_type);
