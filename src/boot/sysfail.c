/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysfail.h"
#include "util.h"

SysFailType sysfail_check(void) {
        return SYSFAIL_NO_FAILURE;
}

const char16_t* sysfail_get_error_str(SysFailType fail_type) {
        return NULL;
}
