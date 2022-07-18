/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <math.h>

#include "macro.h"

/* On some optimization level, iszero(x) is converted to (x == 0.0), and emits warning -Wfloat-equal. */
#define iszero_safe(x) (fpclassify(x) == FP_ZERO)

/* To avoid x == y and triggering compile warning -Wfloat-equal. */
#define fp_equal(x, y) iszero_safe(x - y)
