/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <math.h>

#include "macro.h"

/* On some optimization level, iszero(x) is converted to (x == 0.0), and emits warning -Wfloat-equal.
 * The argument must be a floating point, i.e. one of float, double, or long double. */
#define iszero_safe(x) (fpclassify(x) == FP_ZERO)

/* To avoid x == y and triggering compile warning -Wfloat-equal. This returns false if one of the argument is
 * NaN or infinity. One of the argument must be a floating point. */
#define fp_equal(x, y) iszero_safe((x) - (y))
