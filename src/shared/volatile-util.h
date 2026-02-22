/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum VolatileMode {
        VOLATILE_NO,
        VOLATILE_YES,
        VOLATILE_STATE,
        VOLATILE_OVERLAY,
        _VOLATILE_MODE_MAX,
        _VOLATILE_MODE_INVALID = -EINVAL,
} VolatileMode;

DECLARE_STRING_TABLE_LOOKUP(volatile_mode, VolatileMode);

int query_volatile_mode(VolatileMode *ret);
