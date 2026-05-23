/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <math.h>       /* IWYU pragma: export */

#include "basic-forward.h"

/* On some optimization level, iszero(x) is converted to (x == 0.0), and emits warning -Wfloat-equal.
 * The argument must be a floating point, i.e. one of float, double, or long double. */
#define iszero_safe(x) (fpclassify(x) == FP_ZERO)

/* To avoid x == y and triggering compile warning -Wfloat-equal. This returns false if one of the argument is
 * NaN or infinity. One of the argument must be a floating point.
 *
 * The volatile temporaries force a memory roundtrip, truncating any excess precision (e.g. x87's
 * 80-bit register width for double arithmetic) down to the declared type. -fexcess-precision=standard
 * doesn't fully cover this on x87 — a function return value carried in ST(0) can still arrive at the
 * caller in 80-bit precision (see gcc PR#323), so a value that should compare equal to a
 * same-magnitude literal picks up extra mantissa bits and doesn't. The memory store-and-reload is
 * the one operation guaranteed to truncate. The temporaries inherit the type of the subtraction
 * expression so the macro stays generic over float / double / long double rather than silently
 * truncating wider arguments. */
#define fp_equal(x, y)                                                  \
        ({                                                              \
                volatile __typeof__((x) - (y)) _fp_x = (x);             \
                volatile __typeof__((x) - (y)) _fp_y = (y);             \
                iszero_safe(_fp_x - _fp_y);                             \
        })

